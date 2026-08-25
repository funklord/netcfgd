# 0021: no nano tier

Status: accepted
Date: 2026-07-30
Milestone: M5
Supersedes: [0003](0003-nano-tier.md)

## Context

Decision 0003 kept the nano tier as an opt-in build and wrote down the rule for
re-deciding it:

> **The decision rule at M5:** ship nano only if the DSL compiler and netifrc
> front end together exceed roughly 30% of the 1 MB embedded budget. If the
> compiler comes in at 100 KB there is no tier -- the floor becomes embedded,
> the build matrix loses a column, and this record gets a superseding one.

Two things have happened since. Decision 0019 removed the netifrc front end, so
only the compiler is left on that side of the scale. And M5 opened, so the
measurement is due.

## The measurement

Four binaries, same release profile as the shipping ones (`opt-level = "z"`,
LTO, `panic = "abort"`, stripped), each linking one more thing than the last:

| Build | Size | Adds |
|---|---:|---|
| reconciler + netlink + plan + apply | 637 KB | -- |
| + `serde_json`, one small type decoded | 666 KB | **+29 KB** |
| + the DSL compiler | 830 KB | **+193 KB** |
| + decoding a whole `Document` | 949 KB | **+283 KB** |

**The compiler is 193 KB**, 19% of the embedded budget. Under 0003's threshold
on its own terms, which alone settles it.

**The premise was also backwards.** Design section 10.2 says the compiler is
"disproportionately the bulk of the *size*, since parsers are where formatting
and error strings accumulate". It is not. The hand-written DSL parser costs
193 KB; the code generated from the model's ~85 types to read a compiled
document back costs 283 KB. Nano exists to drop the compiler and read a
compiled document instead -- so a nano build would be **about 120 KB larger
than an embedded one**, while being the tier that cannot show you your own
config.

Note where that cost is *not*: the JSON library itself is 29 KB. Blaming
`serde_json` would have been the obvious wrong conclusion, and project.md
section 6 already carries that guess -- "avoid `serde_json` in the nano tier --
hand-roll a minimal CBOR codec there". A different codec would have saved
nothing, because the expense is the per-type encoder and decoder generated from
the model, not the format they encode into.

## Decision

**There is no nano tier.** Two tiers: `netcfgd-embedded` is the floor and
`netcfgd-full` is the desktop build.

Everything 0003 preserved about legibility comes back for free. A device runs
the config text somebody wrote, `cat` explains the machine, and design section
10.2's "real regression against principle 2" is not taken.

**Nothing about the crate structure changes.** 0003 noted the seam nano needed
already existed for a better reason -- section 5 requires `netcfgd-model`,
`netcfgd-compile` and `netcfgd-plan` to be separate pure crates so the planner
is testable without hardware. That reason is unaffected, and the crates stay
exactly as they are.

## Consequences

**The build matrix loses a column**, as 0003 said it would. One less
configuration to test, and no feature flag whose absence changes what a device
can tell you about itself.

**The 1 MB embedded budget is now the only size target**, and it is not met:
`ncfg` is 1.16 MB and `netcfgd` is 1.50 MB. That is M5's remaining size work
and it is a separate question from this one.

**The measurement points it somewhere specific.** The largest single item is
not a feature but the encoder and decoder generated for the model, and the
second is that two binaries each link most of the workspace --
`size-budget.txt` has flagged the latter since M1. Neither is addressed by
compiling features out, which is what "build tiers" implied the work would be.

**Project.md's guess about CBOR should not be acted on** without re-measuring.
It was reasonable when written and the number says otherwise.

## Alternatives considered

**Keep nano, and make the document format cheaper to decode.** The honest
version of this: the 283 KB is generated code, so a hand-written decoder for a
compact format could be much smaller. It is possible, and it is a large amount
of hand-written parsing of a format with 161 fields -- to produce a tier whose
distinguishing feature is that the operator can no longer read their own
config. The legibility cost was already the argument against nano; paying for
it in hand-rolled decoders as well is worse.

**Keep nano, and bake the compiled document into the binary at build time**, so
it needs neither the compiler nor a decoder. This is the genuinely small
option and it was worth taking seriously -- design section 10.4 already
describes "a factory-default config baked into the read-only image". Rejected
because it is no longer a *tier*: a build whose configuration is fixed at
compile time is a different product with a different operational model, and
`ncfg apply` on it would have nothing to apply from. If somebody wants that,
it is an image-build technique on top of embedded rather than a column in this
matrix.

**Defer the decision again to M6.** Rejected: 0003 asked for a measurement at
M5, the measurement exists, and deferring a decision whose evidence is already
in hand is how an option stays open forever. It also has an ongoing cost --
every field added between now and then is one somebody has to think about nano
for.
