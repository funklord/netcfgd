# 0097: a refused action is not something to wait for

Status: accepted
Date: 2026-08-04
Milestone: found by asking who reads `depends_on`

## Context

[0096](0096-taking-an-interface-down-is-more-than-one-moment.md)'s third break —
deleting a `depends_on` edge — came back **green**, because the test asserted
positions in the action list and actions execute in list order. That raised a
larger question than the test: if execution follows the list, who reads
`depends_on` at all?

Grepping every consumer:

- the **executor does not**. It runs the list in order and stops at the first
  failure;
- `docs/schema/plan.json` pins it, so every client can read it;
- exactly one code path acts on it: `restrict` in the daemon, which filters a
  plan to a set of interfaces and drops an action whose dependency was not kept.

So the edges were a contract with clients and an input to one filter, and
nothing checked the planner emitted them consistently. It did not.

`push` returns `u32::MAX` for an action it declines to emit — an unmanaged
device, or a guard refusing something disruptive — under a comment reading
*"Nothing is emitted, so nothing downstream can depend on it."* Five
accumulators inside the planner (`gates`, `added`, `link_up`, `enslavements`,
`stopped`) collect ids without asking whether they are real, and all five end up
as somebody's `depends_on`. Thirteen call sites; six guard the sentinel and
seven do not.

Two of them are reachable from a config anyone could write:

```
interface br0 { bridge { members = "eth0" }; config = "10.0.0.1/24" }
interface eth0 { master = "br0"; guard = "nfs root" }
```

The guard refuses `link.set_master`, so rule 2 — the master waits for its
members' enslavement — leaves the bridge waiting for an action that does not
exist:

```
DANGLING: link.up  (id 1) depends on 4294967295
DANGLING: addr.add (id 2) depends on 4294967295
```

And that was not cosmetic. `restrict` is how drift is reconciled on one
interface, and given that plan it drops both:

```
kept:    1
dropped: ["link.up on br0 needs action 4294967295, which belongs to another interface"]
```

A machine with a guarded bridge member reconciled the bridge to nothing, and
explained itself with a sentence containing two false claims: there is no action
4294967295, and it belongs to no interface.

## Decision

**`push` drops `u32::MAX` from the `depends_on` it is handed.**

Dropping rather than guarding at each site, for the same reason and in the same
place as the unmanaged check directly below it: a call site added later would
not know to ask. Six of thirteen sites remembered, which is the measure of how
well "remember to check" works.

**Dropping is what the edge means.** An action that was not emitted is not
something to wait for, so the dependency is vacuous rather than unsatisfied. The
alternative — refusing the dependent action too — is wrong on this very
example: the guard is on `eth0`, and refusing to enslave a member is not a
reason to leave the master bare. That is a test rather than a paragraph, because
a fix that dropped the master's actions along with the edge passes every
assertion about dangling ids.

It also makes two comments true that were already written as though they were:
`push`'s "nothing downstream can depend on it", and `restrict`'s "in practice
dependencies stay within an interface, so the orphan case is the master/member
edge and little else."

## The gates

**The invariant is checked on every fixture, not in one test.** `fixtures.rs`
wraps `netcfgd_plan::plan` and asserts, on all 198 plans it builds, that *an
action may only depend on an action that exists and comes before it*. A wrapper
rather than a test because the defect is wherever the next edge is added — five
accumulators, thirteen sites — and not where the last one was.

Three breaks:

- the sentinel reaching `depends_on` again — the state before this — fails the
  named test;
- refusing the dependent action instead of the edge fails it too, on the
  assertion that the bridge is still brought up and addressed;
- every action given an edge to the action *after* it turns **169** of the 198
  red, which is the ordering half of the invariant showing it is live.

A fourth break was written and discarded: it inserted the check *after* the
`retain` that had already removed what it looked for, so it changed nothing and
reported green. §9's rule again — a break that does not apply reads exactly like
a gate that holds.

## What the invariant did not catch

The 197 fixtures that existed before this all pass with the fix reverted. None
of them combines a guard with a master, a gate or a stopped backend, so none
ever produced a dangling edge. The wrapper's value is prospective, and saying so
is the honest reading: it is a gate against the next one, not evidence about the
last one.
