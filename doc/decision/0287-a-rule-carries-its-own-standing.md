# 0287: a rule carries its own standing, and red names its reason

Status: accepted
Date: 2026-10-23
Milestone: M6
Follows: [0286](0286-two-apply-modes-and-values-that-come-from-another-host.md), [0283](0283-firewall-and-queuing-are-in-scope.md)

## What the holder asked for

2026-10-23:

> Ok we need to have a concept of "this rule was not applied fully", like the
> settled status (enough nodes know about the value). So you may have a long
> list of netfilter rules and one of them shows red colour because that machine
> doesn't have kernel support for the rule let's say so it was never applied.

**So status is per rule, and it is standing state rather than a log line.** A
list of two hundred rules with one red row is a different thing from a record
of what the last apply did, and both are needed.

## What exists, and the precedent in it

`ncfg_outcome_t` already gives every action an outcome and a reason, written to
`/run/netcfgd/plan.last.json`: `DONE`, `FAILED`, `SKIPPED`, `REVERTED`.

**And the reason `REVERTED` exists is this decision's own argument, made
once already.** The Rust recorded a revert as log lines; the C made it an
outcome because an operator reading that file after a window closed
unconfirmed could not otherwise tell which of the listed actions were still in
effect -- "which is the one question that file exists to answer, and the one
moment it is read". A rule list without standing has exactly that defect at a
larger scale: it says what was attempted and leaves the operator to work out
what is true.

So the journal stays what it is -- what happened in one run -- and a rule
gains a standing computed from it and from the observation.

## The standing a rule can be in

Each is a state an operator can act on, and each is distinguishable from the
others by what they would do about it:

| standing | means | what the operator does |
|---|---|---|
| `live` | in the kernel, matching the document | nothing |
| `pending` | not applied yet: a dependency is unresolved, or a timed commit has not come | wait, or look at the named node |
| `unsupported` | the kernel refused the construct | change the rule, or the kernel |
| `refused` | netcfgd declined it -- unauthorised, circular, malformed | fix the config |
| `stale` | applied, but a value it depends on has moved | wait for repair, or force it |
| `drifted` | applied, and something changed it underneath | look at what else writes here |
| `unsettled` | applied where it could be, and not every node that needs the value holds it yet | wait, or look at which node |

**Green is the only standing that needs no sentence.** Every other one carries
its reason, in the words the UI shows rather than words a log holds: the
holder's example -- "that machine doesn't have kernel support" -- is a row
whose text must say *which construct* and *which kernel*, because "failed" sends
an operator to a log and "nftables rejected `flowtable`; this kernel is 5.4 and
it arrived in 5.13" ends the question.

**That text does not exist yet, and 0283 says so.** netcfgd currently hands an
operator the kernel's errno; translating `EOPNOTSUPP` from a construct into a
named capability is the half 0283 records as missing, and this is the record
that makes it operator-visible rather than merely tidy. **The red row is the
capability report**, so the two are one piece of work.

## Settled, defined

"Enough nodes know about the value" needs a definition narrow enough to
compute:

**A rule is settled when every node whose rules reference the value holds the
version that carries it, acknowledged, within a freshness bound.**

Three things that definition decides:

- **Not every node -- the consumers.** A value published by one node and
  referenced by three is settled when those three have it, whatever the other
  forty are doing. A quorum over the whole network would make an unrelated
  node's absence into a rule's problem.
- **Acknowledged, not sent.** A node that was sent the version is not a node
  that has it; 0285's whole argument is that distribution is not application.
- **Within a bound, because an acknowledgement ages.** A node that confirmed
  ten minutes ago and is now unreachable is not "settled now", and reporting it
  as settled is the stale-measurement fault this tree keeps finding. The bound
  is the freshness rule the protocol already has to carry.

**Unsettled is a transient and not an error.** It is the normal state for the
seconds after a change, and the reason it must be visible rather than hidden is
that the same appearance -- not yet settled -- is also what a node that will
never settle looks like for the first few seconds.

## Per node, and rolled up without hiding a red

The holder's example is one machine's kernel, so a rule's standing is **per
node first**: a rule can be `live` on nine nodes and `unsupported` on the
tenth, and that is one rule in one list.

**A rollup must not turn that into green.** A list that shows a rule as applied
because most nodes applied it is the vacuous pass this tree keeps meeting in
other clothes -- so the rollup is the worst standing among the nodes, with the
count beside it: `unsupported on 1 of 10`, and the node named on the row's
detail rather than a click away.

## What this asks of the model

- **A rule needs an identity that survives re-planning**, or a list cannot
  show the same row twice. netcfgd has met this before: 0137 took handles for
  tc filters because a planner that cannot name what it installed cannot read
  it back. An authored rule gets a stable id in the config; the kernel object
  gets whatever handle the kernel gives, recorded beside it.
- **Standing is computed, not stored as truth.** It comes from the last run's
  outcome, the observation, and the acknowledgements -- so it cannot drift from
  reality the way a cached status field would.
- **The reason is part of the standing**, not a separate log lookup, because
  the operator reads the row.

## What is not decided here

The wire form of an acknowledgement and whether it rides the same channel as a
directive; the freshness bound's value and whether it is per network or per
rule; whether `pending` distinguishes "waiting for a value" from "waiting for
a commit instant" in the UI or only in the detail; and whether an operator can
pin a rule as expected-unsupported on a given node so that its red stops being
news -- which is the difference between a list that is read and a list that is
dismissed.
