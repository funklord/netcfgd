# 0288: the control path is part of what is being configured

Status: accepted
Date: 2026-10-23
Milestone: M6
Follows: [0285](0285-the-network-is-reconciled-the-way-a-host-is.md), [0286](0286-two-apply-modes-and-values-that-come-from-another-host.md)

## What the holder added

2026-10-23:

> note that for networking the atomicity may also need to cover interface
> configuration or any other subsystem and applied in a sensible order. So it
> is not just netfilter rules etc. It is very common in networking that the
> connection goes down until all parts of a configuration are in place, and for
> us this is bad, because control and decisions come over network.

Three things, and the third is the one that changes the design rather than
widening it.

## Atomicity is a property of a change, not of a subsystem

A jointly dependent change can be an address, a link, a route, an MTU, a
sysctl, a backend, a qdisc or a rule -- usually several at once, which is the
normal shape of "move this network to a new subnet". 0285's two classes were
written with firewall rules in view and they are not about rules: **what makes
a change jointly dependent is that its parts are only correct together**, and
netcfgd's action taxonomy already spans every subsystem that can be in one.

## Ordering already exists here, per host, and is the model for the rest

`plan/build.c` sequences its passes with a reason at each step -- `accept_ra`
before anything derived from a lease, DNS after the leases, the ingress
redirect after the qdisc that shapes the `ifb` it points at, the nftables table
after the forwarding sysctls that give it effect -- and ends with:

> Teardown comes last, so a change to an address is make-before-break: the new
> address is in place before the old one goes. On a machine being reconfigured
> over the network that ordering is the difference between a brief overlap and
> a lockout.

**That is this decision's point, already written and already implemented, for
one host.** What it does not do is reach across nodes, and the network layer
needs the same discipline with a node where a pass stands: add the new subnet
on every node before withdrawing the old from any, bring up the new link
everywhere before taking down the old anywhere.

So the rule is inherited rather than invented: **make before break, teardown
last, and an ordering argued step by step rather than emergent.**

## Where no gap-free order exists, the gap is declared and bounded

Some changes cannot be made before they are broken -- an MTU on a path, a
re-key where both ends cannot accept both keys, a switch between mutually
exclusive modes. For those the connectivity gap is real, and the requirement is
that it is **named in the plan and bounded in the directive** rather than
discovered.

Two consequences, and the second is a trap worth naming:

- **The plan says so**: "this drops the control path for about two seconds",
  in the same sentence where 0286 puts the cost of the other apply mode.
- **The confirm window must exceed the gap.** A node that applies a correct
  change, loses its control path for the duration of that change, and reverts
  because no confirmation arrived has used the safety net to undo something
  that was working. So the window is derived from the declared gap rather than
  left at a default, and a gap longer than the window is a change that must be
  refused or re-staged rather than attempted.

## A directive must be executable to completion offline

This is the rule the holder's third sentence forces, and it is the one that
makes the rest survivable.

**No step of a staged change may require a round trip to finish.** The control
path is part of what is being changed, so the coordinator is exactly what a
node may lose in the middle -- and a node that stalls waiting for an
instruction sits in the half-applied state the whole design exists to avoid.

Which means a directive carries everything: the resolved plan rather than a
template (0286), its effective instant rather than a later "go" (0285), its
confirm window, and its revert. A node that is cut off part way through
**finishes, then decides** -- and deciding is local, because the revert timer
is local.

## netcfgd will not become smart enough to prevent this, and should not try

The holder, while this record was being written:

> I am hoping you can prove me wrong, but I find it unlikely netcfgd will
> become smart enough to never hose its necessary connections. This will
> probably remain an operator responsibility.

**That is right, and the attempt to prove otherwise is where the design would
go wrong.** The reasons are structural rather than a matter of effort:

- **The topology is outside the machine.** Whether the uplink's VLAN is carried
  by the switch two hops away, whether the operator's session comes through a
  jump host, whether a route being replaced is in somebody else's path --
  netcfgd cannot see any of it from a node, and a tool that acts as though it
  could is more dangerous than one that admits it cannot.
- **A correct change can still break connectivity**, through a switch's MAC
  table, an upstream firewall's conntrack, an ISP's lease. Nothing in the
  document predicts those.
- **Intent is not derivable.** "This change cuts the path my instructions
  arrive on" and "this change *moves* my instructions to a new path, which is
  what I was asked to do" look identical from inside. A tool that refuses the
  second to prevent the first is a tool that cannot perform a migration.

So the target is not prevention. **The target is that an operator's mistake is
survivable**, which is a different and achievable thing, and most of it is
already built:

- **Detect and declare, which needs no topology knowledge.** Saying "this
  changes the address your instruction arrived on" is local, cheap and useful,
  and it leaves the decision where the holder puts it.
- **The local revert timer, which is the mechanism that actually helps.** It
  does not require netcfgd to be clever -- only to be able to undo, and to
  decide without being told. That converts "be careful" into "you get a second
  chance", and 0094 and `confirm.c` are it, on one host, today.
- **Make before break**, which shrinks the window without understanding
  anything about the network: `plan/build.c` already does this and says why.
- **One refusal netcfgd can actually justify**, below.

### The one case it can decide locally, and the one it cannot

**It can prove that a revert would not restore what it came from.** That is
local knowledge: the pre-change state was reachable by construction, so a
revert into a state the coordinator could not reach is detectable without
knowing any topology -- and arming a timer whose expiry lands somewhere
unreachable is worse than not arming one, because it turns a recoverable
mistake into two.

**It cannot prove that a change is safe**, and must not imply it. A plan that
touches the control path says so and proceeds; an operator who knows about the
jump host, the maintenance window or the migration is the only one who can
weigh it.

### What knowing the control path is for, then

Not a veto. Three things, in increasing order of value:

- **Order it last**, which generalises the teardown rule: among changes that
  must happen, the ones touching the control path go after those that do not,
  so an earlier failure is still reportable over a path that still works.
- **Say so**, so the operator's decision is informed rather than blind.
- **Choose the window.** A change that touches the control path wants a confirm
  window long enough for the path to come back, and netcfgd can derive that
  from the change rather than leaving it at a default.

**And today it knows none of this.** `SO_PEERCRED` identifies the local peer
process -- a uid and a pid -- and the bridge holds the network connection
without reporting which interface, address or route it arrives over. So the
planner cannot currently tell that the address it is about to replace is the
one the instruction came in on, which is the cheapest of the three and the
precondition for the other two.

## What is not decided here

How the bridge reports the control path and in what terms -- an interface, an
address, a route, or the peer it is talking to; whether a node reached over two
paths treats both as control; how the declared gap is measured rather than
guessed; what the ordering is *across* nodes when two of them each carry the
other's control path, which is the cross-host form of the same question; and
whether an operator may mark a path as expendable for one change.

**What is settled is where the responsibility sits.** netcfgd declares, orders,
and can undo; the operator decides. A later record may narrow the cases netcfgd
can refuse on its own evidence, and none of them will add up to a guarantee.
