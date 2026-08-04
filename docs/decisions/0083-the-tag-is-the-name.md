# 0083: the tag is the name

Status: accepted
Date: 2026-08-04
Milestone: M8, closing the question [0082](0082-one-operation-has-one-name.md) left open

## Context

[0082](0082-one-operation-has-one-name.md) established that every operation had
two names -- serde's `snake_case` of the variant on the wire, `Op::name()`
everywhere else -- and fixed the symptom by sending `op_name` beside the op. It
recorded the better answer as rejected-for-now:

> **Renaming the tags themselves** [...] Better design -- redundancy is what went
> wrong here, and this adds more of it -- and not taken now for two reasons. It
> is a breaking change to a pinned surface, and it is the kind of change whose
> value is judged by whoever maintains the protocol rather than by whoever
> noticed the symptom.

Judged. Taken.

## Decision

**Each `Op` variant names itself on the wire, and that name is `Op::name()`.**

```rust
#[serde(tag = "op")]
pub enum Op {
	#[serde(rename = "link.create")]
	LinkCreate { .. },
```

`rename_all = "snake_case"` is gone from the container, and `Action::op_name`
is gone with it -- one name means nothing to carry beside the op.

`docs/schema/plan.json`: 96 changed, 144 removed. **Major.** Any client reading
an op tag reads a different string from this release on.

## What it found

`ncfg tui` has been showing the wrong word since it was written. Its plan pane
reads the tag:

```rust
let op = action.get("op").and_then(|op| op.get("op"))
```

which was `link_create`, while `ncfg plan` beside it printed `link.create`. Its
unit test did not catch that, because the fixture is hand-written and says
`"op": {"op": "addr.add"}` -- a fixture agreeing with itself about a spelling
nothing produced. That is precisely the failure `docs/schema/` exists to
prevent, in the one crate whose tests predate the witness.

Both are now true without anything else changing: the TUI reads the tag, the
tag is the name, and the fixture became honest by accident. Left as it is rather
than rewritten to read from the witness -- that is a separate piece of work on
the TUI's tests, and worth doing.

So this was never a two-client problem. Three clients rendered plans and two of
them showed a name that appears nowhere else in netcfgd.

## The gate

Renaming the tags trades one risk for a subtler one. There are now two lists of
forty-seven strings -- the `#[serde(rename)]` attributes and the `name()` match
-- and nothing about the language makes them agree. The next op added by copying
its neighbour would get one of them right.

`every_op_serialises_as_the_name_it_reports` serialises every op in the
exhaustive sample and asserts the tag equals `name()`. It is not a spot check:
`every_op()`'s match has no `_` arm, so a new variant is a compile error in the
sample file before it can reach this assertion.

It earned itself immediately. `CommitConfirm` is the one unit variant among
forty-eight, the mechanical edit that added the renames matched only variants
with a brace, and it silently became `"CommitConfirm"` on the wire when
`rename_all` was removed. The gate failed on its first run, naming it.

Both deliberate breaks fail too: a tag that disagrees with its name, and a
variant with no rename at all.

## What this does not break

Nothing persisted. `/run/netcfgd/plan.last.json` holds a `Journal`, whose
records store the op as `Op::name()` and always did; `desired.json` holds a
`Document`, which has no `Op` in it. No file written by an older netcfgd is read
back as a plan, so there is no upgrade path to write.

A client built against the old tags does break, which is what a major bump
means. `client/` reports whatever tag it finds -- an old daemon puts
`link_create` in the op column, which is wrong and readable, where insisting on
the new spelling would leave the column empty. A plan that will not say what it
is about to do is not a plan.
