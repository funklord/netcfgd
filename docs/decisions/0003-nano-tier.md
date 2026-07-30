# 0003: the nano tier stays optional, and is re-decided at M5 by measurement

Status: superseded by [0021](0021-no-nano-tier.md)
Date: 2026-07-28
Milestone: M5 (the seam exists from M1)

## Context

`project.md` §8 question 3, design §10.2 and §19.2. The nano tier omits the
DSL compiler to fit under 400 KB, so a nano device's stored configuration is
a compiled document rather than readable text. `cat` stops explaining the
box. That is a real violation of principle 2, and the design doc says so
plainly rather than glossing it.

## Decision

Keep the tier as an opt-in build. Make `netcfgd-embedded` the default floor.
Re-take the ship/no-ship decision at M5 against a measurement rather than
against the current guess.

**Keeping the option costs almost nothing now.** The seam nano needs already
exists for an unrelated and stronger reason: §5 requires `netcfgd-model`,
`netcfgd-compile` and `netcfgd-plan` to be separate pure crates so the
planner is testable against fixtures without hardware. Nano is that seam plus
a feature flag.

**Nothing before M5 may be shaped by nano.** No API narrowed, no type
simplified, no format chosen because nano might want it. If that rule is
being bent, the tier is already costing more than it is worth.

**Invariants nano must satisfy, or it does not ship.** `ncfg plan`, `ncfg
explain` and `ncfg show --json` all work on it. §1 constraint 7 already
requires plan; the other two are what keep the principle-2 regression bounded.
"Readable with `cat`" degrades to "readable with one command that is in the
400 KB build" — not to "readable only from another machine". The document
also carries `generated_by` and a hash of the source config, so a device's
state ties back to a specific file in the image's build tree.

**The decision rule at M5:** ship nano only if the DSL compiler and netifrc
front end together exceed roughly 30% of the 1 MB embedded budget. If the
compiler comes in at 100 KB there is no tier — the floor becomes embedded,
the build matrix loses a column, and this record gets a superseding one.

## Consequences

Three build profiles through M5, and §6's size and footprint gates cover all
three from commit 1. That is more CI setup than a two-tier decision would
need, and it is the main cost of deferring.

If nano is dropped at M5 the cost is deleting a feature flag, not a redesign.
That asymmetry is the whole argument for deferring rather than deciding now.

## Alternatives considered

**Drop nano now; floor at embedded.** Tempting, and it is the cleaner story.
Rejected because it throws away the one deployment shape where nano is *not*
a regression, and does so before any measurement exists. Design §10.4 already
describes a read-only squashfs root with a factory-default config baked into
the image — on such a device the configuration is authored on a build host
and shipped as an artifact, so the plain text does exist, upstream, in the
image source. That case is narrow (headless appliances, host-built images)
and it is real.

**Commit to shipping nano now.** Rejected: every number in §10.2 is a budget
to validate, not a measurement, and the differentiator against netifd is not
size alone.

**Nano stores the source text compressed alongside the document.** Rejected
twice over: flash is the constrained resource on exactly these devices, and
the text is useless without the parser that nano exists to remove — so it
would restore the bytes and not the capability.

## Superseded, 2026-07-30

By [0021](0021-no-nano-tier.md), against the measurement this record asked for.
The compiler came in at 193 KB -- under the 30% threshold above -- and decoding
a compiled document costs 283 KB, so the tier that exists to avoid the compiler
would have been the larger of the two.

The rule in this record worked exactly as intended: it named a number, deferred
the decision to a point where the number could be taken, and the number said
no. Kept rather than deleted for that reason.
