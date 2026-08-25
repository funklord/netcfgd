# 0006: addressing sources compose, and composition has seven rules

Status: accepted
Date: 2026-07-28
Milestone: M1

## Context

`project.md` §8 question 6. §2.1 makes `addressing` an ordered list of
`AddressSource` that may be empty, and the design assumes the sources compose
rather than being alternatives. That assumption is correct but underspecified:
"ordered list" does not say what the order is *for*, nor what happens when two
sources want the same thing.

## Decision

Composition is confirmed, and it is not optional. Dual-stack alone forces it —
`Dhcp4` plus `Slaac` on one interface is the ordinary case and cannot be
expressed by an exclusive field. Static-plus-DHCP, a fixed management address
alongside a leased one, is the other common shape.

Seven rules give it meaning.

**1. Multiplicity.** At most one each of `Dhcp4`, `Dhcp6`, `Slaac` and
`LinkLocal` per interface; any number of `Static`. Two DHCP clients on one
link is always a bug, so it is a compile error rather than a runtime race
nobody can reproduce.

**2. Order is not execution sequence.** The planner may start backends
concurrently; §4's DAG edges are the only sequencing that exists. Order in the
list is significant for exactly two things — rules 3 and 4 — and for nothing
else. This has to be stated, or "ordered" is a promise the reconciler does not
keep.

**3. Default route metrics derive from list position:** `base + index * step`,
unless the `Route` carries an explicit `metric`. This is what makes "static
first, DHCP second" mean the obvious thing, deterministically, and it lets
`ncfg explain` report a metric as a position in a list rather than as a number
from nowhere.

**4. DNS merges in list order**, deduplicated, first occurrence winning, and
then the interface's merged result composes over globals as §2.1 already
specifies.

**5. `LinkLocal` coexists; it is not a fallback.** RFC 3927 permits an IPv4
link-local address alongside a routable one, so `LinkLocal` means "configure
169.254/16 here" unconditionally. A timeout-triggered fallback would be state
hidden inside the reconciler that no file explains, which is the opposite of
the product.

**6. An empty list is legal** and means "manage this link, add no addresses".
Bridge and bond members need it, and so does any L2-only interface.

**7. Sources reconcile differently when their address goes missing**, and this
is where composition actually bites. A missing `Static` address is re-added
directly: the config says it should be there. A missing `Dhcp4` address is
**not** re-added — the lease is what is gone, so the correct action is
`backend.restart`, not `addr.add`. Both objects are ours under the decision
0002 tag; what differs is which op the planner emits. Getting this wrong
produces an address that reappears with no lease behind it and expires
again immediately, which looks like a flapping interface and is not.

## Consequences

The compiler needs multiplicity validation (rule 1), the planner needs metric
derivation from list index (rule 3), and the observed model must attribute
each address to the source that produced it, or rule 7 cannot be implemented
at all.

That attribution is per-address state in `/run`, and it is the same state the
pre-5.18 `IFA_PROTO` fallback needs in decision 0002. One mechanism with two
consumers — build it once, and make sure the second consumer is known about
before the first one's design is fixed.

Rule 7 also means the fixture harness (§5) needs observed snapshots where an
address is *absent*, not just wrong. An address that differs and an address
that vanished produce different plans, and only the second exercises the
distinction.

## Alternatives considered

**Exclusive: one source per interface.** Rejected — it cannot express
dual-stack, which is not an edge case.

**An unordered set.** Rejected: rules 3 and 4 then need explicit metrics and
explicit DNS precedence in every config that has more than one source, which
is more configuration for the common case in exchange for nothing.

**Order means execution sequence.** Rejected: it would serialise DHCPv4 behind
DHCPv6 for no reason, and §4's DAG is already the mechanism for the ordering
that genuinely matters.

**`LinkLocal` as an automatic fallback after a DHCP timeout.** Rejected under
rule 5, and worth naming because it is what most tools do. It puts a timer and
a hidden state machine between the config file and the observed state, and
then `ncfg explain` has to account for an address no file asked for.
