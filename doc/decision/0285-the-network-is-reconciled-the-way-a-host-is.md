# 0285: the network is reconciled the way a host is

Status: accepted
Date: 2026-10-23
Milestone: M6
Follows: [0284](0284-the-ruleset-is-netcfgds-and-rules-arrive-in-five-layers.md), [0269](0269-the-remote-half-is-a-separate-program.md)

## What the holder described

2026-10-23, after 0284:

> We have our netcfgd fuzznet layer with config that is attempted to be kept
> atomic across the whole network via fuzznet, and occasionally fixed when
> changes need to occur (can be driven from kernel updates). From that data
> then we have the process of planning and provisioning it out to the nodes and
> monitoring for changes and possibly repairing.

**That is netcfgd's own loop, one level up**, and naming it that way is the
decision: a network-wide document, a plan per node, provisioning, observation,
and repair of what drifted. The host loop is observe, plan, apply, confirm,
repair; the network loop is the same five words with a node where an interface
stands.

So the vocabulary is reused rather than reinvented. Design section 4's action
taxonomy, the drift reporting, the confirm-and-roll-back machinery and the
word "repair" all mean at network scale what they already mean on a host, and
a reader who knows one knows the other.

## Atomicity is a requirement for some changes, and the answer is not a promise

The holder, when this record said atomic application was unachievable and
offered visibility instead:

> the think about atomicity is that some changes need to be applied that way,
> or else the system goes down

That is right and the earlier framing dodged it. "Nodes converge eventually,
and the window is visible" is a true statement about a medium and a useless one
about a renumbering: if half the nodes move to a new subnet and half do not, the
halves cannot talk, and nothing about the window being *visible* makes the
network work while it is open.

So the model has two classes of change, and **classifying a change is part of
planning it** rather than something an operator is left to know:

- **Independently safe.** A node can apply it alone and partial application
  degrades rather than breaks: a local qdisc, a one-sided filter, a hook.
  These roll forward per node, and visibility is genuinely the obligation.
- **Jointly dependent.** Correctness requires all or none: a subnet or VLAN
  renumber, a rotated pre-shared key or WireGuard peer key, a policy both ends
  must agree on, a routing or MTU change along a path. Applied to some nodes
  only, these do not degrade -- they partition.

### Make before break, which removes the need for a distributed commit

Most jointly-dependent changes can be split into two independently-safe ones:
add the new before withdrawing the old. Both addresses live on the interface,
both keys are accepted, both VLANs are trunked, the new policy runs beside the
old -- then, once every node reports the new state, the old is withdrawn as a
second change that is itself safe to apply piecemeal.

**This is the preferred route and the planner should prefer it**, because it
needs no agreement at all: each step is safe alone, and the network is correct
throughout. It costs a second pass and a transient state in which both
configurations are live, which is a far smaller cost than a commit protocol.

### Simultaneous application is the requirement, so the directive carries its instant

The holder, narrowing it:

> by system I mean a distributed system, so they all need to apply after
> receiving directives simultaneously

So the primitive is not "apply when you receive it" but **distribute first,
apply together**, and the two phases are separate on purpose:

1. **Distribute.** Every node receives the directive and holds it, applied to
   nothing. It plans against it -- parses, builds the plan, renders the
   nftables transaction, opens what it needs -- so that nothing expensive
   remains to be done later.
2. **Apply at the instant the directive names.** Not on a "go" message: the
   directive carries its own effective time, and each node applies at that
   time by its own clock.

**The clock is the synchronisation primitive, and that is the point.** A "go"
broadcast makes simultaneity depend on one message arriving everywhere at once,
which is the thing a network cannot promise -- lose it to one node and that
node is the partition. An absolute instant distributed in advance survives
message loss: a node that has the directive applies on time whether or not it
hears anything further.

**Three consequences, and the first does not exist yet in this tree.**

- **A node must know whether its clock can be trusted, and refuse a timed
  apply when it cannot.** netcfgd reads `CLOCK_MONOTONIC` in four places and
  asks the kernel nothing about clock discipline -- `adjtimex`, `ntp_adjtime`
  and `ntp_gettime` appear nowhere. A node whose clock is minutes out applies
  minutes early or late, which is precisely the half-applied renumbering this
  mechanism exists to prevent, so the prerequisite is a readable answer to
  "how far out might I be" and a refusal when the answer is "unknown". The
  kernel gives it: the maximum error and the synchronised flag.
- **Planning happens before the instant and committing happens at it.** All of
  this daemon's expensive work is already separable that way -- a plan is built
  and then applied, an nftables transaction is assembled and then sent -- so
  the apply at T is a commit of prepared work rather than a configuration run
  that takes an unpredictable time and desynchronises by itself.
- **A node that missed the window does not apply late.** For a
  jointly-dependent change, applying after the others have moved on is worse
  than not applying: it is a second partition where there was one stale node.
  It reports stale, and the repair loop brings it to the current version by the
  ordinary path.

### Stage, arm, confirm is the safety net under it, and netcfgd already has it

A simultaneous apply can still be wrong -- the directive may be bad, or correct
and still break a path nobody predicted -- so the timed commit is wrapped in
the mechanism this daemon already runs on one host:

1. each node applies at T and **arms its own revert timer** -- `confirm.c`,
   the window `global { confirm = N }` sets, with `ncfg_apply_revert` replaying
   the inverses and re-planning;
2. the coordinator **confirms** once every node reports the new version live;
3. a node that does not hear the confirm **reverts itself**.

**The node's own timer is what makes this partition-safe.** No message is
needed to roll back, so a node cut off after applying returns to the state the
rest of the network is in rather than sitting in a half-applied one.

Two properties it depends on, both already decided here:

- **The revert record survives the process**, which is why `confirm.c` keeps
  its two files in a sibling of the run directory rather than inside it: an
  init that clears `/run` on a stop would otherwise destroy the only record of
  what to go back to (0163). At network scale it must survive a reboot too,
  which that placement already gives.
- **Rollback must restore the path the coordinator uses.** The pre-change state
  is known-good *and* reachable; that is what makes the timer a safety net
  rather than a way to lose a node twice.

### The change that must be refused rather than staged

A change whose rollback cannot restore reachability -- re-keying the control
plane itself with no second channel, or renumbering the network the coordinator
is reached over -- has no safe automatic form. Staging it arms a timer that
cannot be confirmed and cannot be recovered from.

**Those need a second channel or an explicit operator override, and netcfgd
should say so rather than discover it.** It is the branch-you-are-sitting-on
case; a tool that applies it silently and a tool that refuses it both beat one
that stages it and hopes.

### The epoch is this design's generation counter, and that is not a coincidence

The thing being built this week for one ruleset is the same mechanism at a
third scale:

| scale | handle | question it answers |
|---|---|---|
| ruleset | the kernel's nftables generation | did this ruleset move while I read it |
| host | observed against desired | is this machine what the document asks |
| network | the config version a node holds | is this node on the truth everyone else is on |

A counter that says "what you are looking at has moved" is how each layer
avoids acting on a stale view. Writing it down here means the network layer
does not invent a fourth vocabulary for it.

## Kernel updates are an amendment driver, and they want a capability report

"occasionally fixed when changes need to occur (can be driven from kernel
updates)" names the case that makes a network config a living thing rather
than a file: a node's kernel changes under it, and what the config asks may no
longer be what that kernel can do -- or may newly be something better.

Two consequences, and the first is already named as missing:

- **A node that cannot comply must say what it could not do**, by name.
  [0283](0283-firewall-and-queuing-are-in-scope.md) records that netcfgd does
  not yet translate a kernel's `EOPNOTSUPP` into "this kernel is too old for
  X"; at network scale that absence turns one node's kernel difference into a
  provisioning failure with no remedy in it. This is where that work earns its
  keep.
- **An amendment is a version, not an edit in place.** A fix driven by a
  kernel update is a new version distributed the same way as any other, so
  that a node which was offline for it converges rather than being
  special-cased.

## What is not decided here

How a directive's effective instant is chosen -- far enough ahead that every
node has it, close enough that an operator is still watching; who holds the
authoritative config and whether that is netcfgd on a node or a separate
program; how a version is agreed when two writers amend at once; what
a node does when it cannot comply -- hold its last good config, apply the part
it can, or refuse the version whole; how a partition is reported and what heals
when it closes; whether a node may ever refuse a config it is authorised to
receive; and how a local document and the distributed store are reconciled when
both have moved, which is the question "all of the config lives there" asks
and does not answer.

**And the sequencing is its own question.** The dependency is unfinished, so
netcfgd either waits, or designs against the model and implements behind a seam
it can test without a network -- which is what it already does for every other
kernel-facing thing, and what `ncfg_observe_kernel_t` is. Which of those, and
how much is built before fuzznet can carry it, is the holder's.

0284's requirement stands over all of it: **a node keeps enforcing when the
controller is unreachable, and must not fail open.** A network loop that can
leave a node unprotected while it waits for instructions has chosen the one
failure nobody is watching for.
