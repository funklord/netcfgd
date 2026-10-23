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

## Atomic is the right intention and the wrong promise, so say which

The holder's word is "attempted", and that is exact. What is achievable is
worth separating from what is not, because the difference decides what the
software must *show* rather than what it must do.

**Achievable: one authenticated version of the truth.** A network config can
be versioned, signed and distributed so that every node can say which version
it holds and refuse an older one. What that needs from a protocol is framed
authenticated datagrams, capability chains against a pinned root, chunking
with reassembly, and frame freshness -- which is `doc/shared-protocol-brief.md`
section 2, and that document says in its own header that it states netcfgd's
**requirements** rather than a design.

**fuzznet is not complete, on its holder's word, 2026-10-23**, and this record
says so where a reader meets the requirement rather than further down. The
brief's "everything in that list is built" is a reading taken on 2026-08-19 of
a tree that is not this one, which `evidence.md` calls a measurement nobody
here took; it is overtaken and the brief now carries the date. **So nothing in
netcfgd may be planned as though the dependency were finished**, and a fault
found in it is signalled to that project rather than fixed from here.

**Not achievable: atomic application.** Nodes apply at different instants,
some are asleep, a partition splits the network mid-rollout. Authenticated
distribution is not consensus, and nothing in this design should be read as
implying that a messaging library provides one.

**So the obligation is visibility, not atomicity.** A window where nodes hold
different versions is a fact of the medium; what must never happen is that
window being invisible. Which node holds which version, and for how long, is
state the network loop reports -- in the same way a host reports an interface
whose observed state does not match the document.

### All of the config, not only the network-wide part

Stated the same day: netcfgd wants fuzznet's distributed model to store **all**
of its configuration. That is larger than 0284's layer 3 and it changes where
the desired state lives: a host's document becomes a projection of the
distributed store rather than the original, and "the config" stops being a file
on a machine.

Two things follow, and the second is a hard requirement rather than a
preference.

**The store is the subject of the reconcile loop, at both scales.** A node
holds a version; the loop compares what the node has against what the store
says and repairs the difference. That is the same comparison the host loop does
between observed and desired, which is why this is one design and not two.

**A host still has to come up alone.** A node boots before the network exists,
a read-only root cannot write a cache, and a machine whose uplink is the thing
being configured cannot fetch its own configuration over it --
`doc/first-run.md` and `doc/read-only-root.md` are this tree's existing
statements of that. So a local document remains authoritative for a node in
isolation, and the distributed store is what a node converges *to* when it can
reach it. A design in which a node cannot configure its own link without the
network is a design that cannot bring up the network.

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

Who holds the authoritative config and whether that is netcfgd on a node or a
separate program; how a version is agreed when two writers amend at once; what
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
