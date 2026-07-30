# 0019: no importers for config stores that rewrite themselves

Status: accepted
Date: 2026-07-30
Milestone: M4

## Context

The M4 row lists "netifrc compat + `ncfg convert`, importers (`nm`,
`networkd`, `uci`)". Four adapters reading four foreign formats, scheduled
immediately before the schema freeze.

They were scheduled there for a reason that turns out not to require them, and
the objection to building them is stronger than the one usually made.

## Decision

**No importers for NetworkManager or systemd-networkd. No netifrc front end.
No `ncfg convert` in the core.** `uci` is deferred to M5 rather than dropped.

### The NM and networkd case: the source is not stable

The usual argument against importers is effort against a small audience. The
real one is that **NetworkManager and networkd rewrite their own
configuration**. A keyfile is not a document somebody wrote; it is a cache the
daemon edits as connections come and go. Importing from one is snapshotting
something that moves.

This project has already decided this once. Decision 0014 refused iwd because
it "keeps its own network database and writes to it", making it "a second
source of truth that writes itself" -- and iwd was refused as a *mechanism*,
where netcfgd would at least have been watching it. An importer is worse: it
reads once and walks away, and the operator finds out months later that the
config they imported was mid-edit.

There is a second-order harm. An import that mostly works produces a netcfgd
config nobody wrote and nobody can fully explain, which is the opposite of what
constraint 1 is for. The migration this project wants is somebody reading their
old config and writing a new one they understand.

### The netifrc front end is the expensive item

Not the importer -- the *front end*. Project.md section 6 has it as a
permanent second parser behind a feature flag, with its own fuzz target in the
CI table. That is a dialect to support indefinitely, for an audience that is
mostly one distribution.

What netifrc was worth has already been extracted and does not depend on
reading a single file of it: decision 0001 took the vocabulary and rejected the
syntax, and decision 0011 found the `preup` ordering trap, which is the most
useful thing to come out of the comparison and is written down independently.

`ncfg convert` is a weaker case in both directions. It is cheap and one-way,
and netifrc files really are hand-written and stable, so the objection above
does not apply to it. But it needs nothing from the core, so if somebody wants
it later it is a script rather than a decision to revisit.

### uci is deferred, not dropped

OpenWrt is a declared target: M5 is build tiers, procd integration and
read-only root. uci files are hand-edited, stable, and not rewritten behind the
operator's back, so the objection above does not reach them either. An importer
belongs next to the rest of the OpenWrt work rather than three milestones
early.

### What the importers were actually buying

They were scheduled immediately before the freeze deliberately: reading a
foreign format is how a model gap gets found while the schema can still absorb
one. That reasoning was sound and it is the only real loss here.

It does not require building anything. **Reading the four formats and
comparing them against the model gets the same answer**, in an afternoon rather
than a milestone, and it is what happens instead -- before the freeze, and
recorded wherever it turns something up.

## Consequences

**M4 loses four deliverables and the freeze arrives sooner.** What is left is
PPPoE, the format audit, and the freeze itself.

**Project.md's milestone table and section 6 are now wrong** and are corrected
rather than left to be discovered. The CI table's "netifrc" fuzz target goes
with the parser it was for.

**Somebody migrating from NetworkManager writes their config by hand.** That is
a real cost and it is the intended one. A tool that produced a working config
they did not understand would be worse for them the first time it broke.

**Decision 0003's nano-tier rule mentions netifrc** -- "ship nano only if the
DSL compiler and netifrc front end can be compiled out". With no front end the
condition is simply smaller, which does not change that decision's answer.

## Alternatives considered

**Build them anyway, for adoption.** Rejected. An importer is an adoption
argument, and this project's adoption argument is that the config is
predictable and explainable. Handing somebody a generated file they cannot
account for spends the thing being sold.

**Import from NM's D-Bus rather than its keyfiles**, so the source is at least
live. Rejected: it needs the D-Bus client decision 0014 already declined to
build, to read a store that would still be rewritten afterwards.

**A read-only `ncfg import --dry-run` that prints what it would produce
without writing it.** Genuinely tempting -- it makes the operator read the
result, which answers the "config nobody wrote" objection. Still rejected for
NM and networkd, because the input is unstable whatever is done with the
output. It is the shape to use if uci lands in M5.
