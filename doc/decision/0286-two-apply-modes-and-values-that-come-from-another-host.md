# 0286: two apply modes, and rules that need another host's value

Status: accepted
Date: 2026-10-23
Milestone: M6
Follows: [0285](0285-the-network-is-reconciled-the-way-a-host-is.md)

## The three questions

The holder, 2026-10-23:

> What this really means is that we need to handle both best-effort and atomic
> apply. Maybe that is a choice that is made at the bottom of the UI when you
> click an apply button or something? Do we apply these settings ad-hoc or do
> we collate and run them on each node once the config is provisioned to each
> one. What about rules that depend on a value from another host? etc.

Both modes, yes. The second and third questions answer each other, and the
third is the one that constrains everything.

## Both modes, said precisely

**Best-effort.** Each node applies as soon as it has the config. A node that
cannot do all of it does what it can and **reports the rest**; a node that is
absent converges when it returns. Partial application is a state the loop
shows, not a failure. This is the right mode for everything 0285 calls
independently safe, and it is what the host loop already does.

**Atomic.** Nothing is applied until every node holds a fully resolved plan;
then all apply at the instant the directive names, each arming its own revert
timer (0285). A node that cannot take part is a reason **not to start**, not a
node to leave behind.

## Who chooses, and why it is not a bare dropdown

The mode is a property of the change rather than of the operator's mood, and
netcfgd can tell which: 0285's two classes are derivable from the plan -- a
renumber, a rotated key, a two-sided policy are jointly dependent, and a local
qdisc is not.

**So the planner classifies, proposes, and says what the other mode would
cost.** At the bottom of that apply button the useful text is not "atomic or
best-effort?" but "this renumbers four nodes; applied best-effort they cannot
reach each other until the last one lands". A control that asks a bare question
pushes a correctness decision onto a dropdown, and the operator answering it
usually has less information than the planner that drew it.

**The override stays, because the operator knows things netcfgd does not** -- a
maintenance window, a lab, a node that is deliberately off. What netcfgd owes
is the consequence in the sentence, not the choice.

## Collate or ad-hoc follows from the mode, and one detail is load-bearing

Atomic **requires** collate: resolve, distribute, then commit together.
Best-effort may be ad-hoc, which is the cheaper path and the common one.

**What is distributed in atomic mode is the resolved plan, not the config
template.** A template still carrying "the address node B got" resolves
differently on each node -- or not at all on a node that has not heard from B
-- so distributing the template and applying simultaneously would apply
*different things* at the same instant, which is worse than applying the same
thing at different instants. Resolution is therefore a step of the network
plan, before distribution, and a plan that cannot be resolved is a change that
does not start.

## Rules that need another host's value

Some values are **authored** -- an operator writes `10.0.0.0/24` -- and some
are **discovered**: a DHCP lease, a generated key, an address the kernel chose,
a prefix delegated upstream. A rule naming a discovered value cannot be
resolved until the node that discovers it has published it.

**netcfgd already has this shape at host scale, and the contract is written
down.** `reported.c` and `doc/interface-report.md`: a cellular bearer or a
tunnel daemon knows the configuration it negotiated, netcfgd does not, so the
value arrives through a file under `/run/netcfgd/reported/` and netcfgd
installs it tagged as its own. A cross-host dependency is that one level up --
the node is the reporter and the store is the file.

**And that pass's gate is the one to copy, not just its shape.**
`ncfg_plan_takes_reports` is deliberately not "there is a file": a report for
an interface the document says nothing about is an observation with no
instruction behind it. The network analogue -- a node publishing values nobody
referenced changes nothing -- keeps a published value from being an
instruction, which is what stops a compromised or confused node from
configuring its neighbours.

### What each mode does with an unresolved dependency

- **Best-effort: pending and reported, never silently dropped.** The rule is
  not installed, the reason names the value and the node it waits on, and the
  loop keeps it visible. A rule that vanishes because its dependency has not
  arrived is the worst available behaviour, because the operator reads a
  successful apply.
- **Atomic: a precondition, so the change does not start.** With a reason, and
  the reason names the node that has not published. A timed commit over a plan
  with a hole in it is a timed partition.

### A resolved plan is a snapshot, so dependencies carry versions

Node B's lease changes and the rule that named its address is now wrong. That
is not an error -- it is the ordinary case -- and it means a resolved plan
records **which values were discovered and at which version**, so that a
change in a dependency re-triggers resolution and the repair loop carries the
new value out.

This is 0285's counter at a fourth scale: a ruleset's generation, a host's
observed-against-desired, a node's config version, and now a dependency's
version. Four places, one idea: know whether what you acted on has moved.

### Cycles must be refused, and the common case that looks like one is not

A depends on a value B discovers, B depends on a value A discovers: resolvable,
and common -- two nodes peering with each other's public keys. Both discover
independently, both publish, both resolve. **Discovery does not depend on the
rule**, which is what makes it fine.

A true cycle is one where it does: A's address is computed from B's, and B's
from A's. That has no fixed point and a planner that iterates on it hangs.
**Refuse it, naming both ends**, and do so at resolution time rather than at
apply time -- a planner that loops is worse than one that says "circular",
because the second can be read.

## What is not decided here

How a published value is named so that a rule can refer to it; what authority a
node needs to publish one (0284's narrower-than-admin tier question, now with a
second use); how long a published value lives without being refreshed; whether
a best-effort apply may be promoted to atomic mid-flight when it turns out to
have been misclassified; and what the UI shows for a change that is partly
jointly dependent -- a renumber of two nodes beside a qdisc on a third.
