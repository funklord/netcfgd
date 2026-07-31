# 0038: Versioning starts at the first release

Status: accepted
Date: 2026-07-31
Milestone: applies from now until the first release

Supersedes the schema-version paragraph of [0037](0037-clear-then-unmanage.md),
which recorded a minor bump that is now not taken.

## Context

`schema_version` reached 1.2 by the ordinary route: fields were added, and
project.md section 2 says adding a field bumps minor. Decision 0037 bumped it
last, for `Device.on_unmanage`.

netcfgd has not shipped. There is no consumer anywhere that was built against
1.1 and could be handed a 1.2 document.

## Decision

**The schema version stays at 1.0 until the first release. Interfaces start
being versioned when they are shipped.**

A version number is a promise to somebody: *this is what you can rely on, and
here is how you tell whether the thing in front of you is compatible*. Before a
release there is nobody to promise it to, so counting bumps through a schema
that is still being designed measures how much work has happened rather than
what anybody can depend on. A field added and removed in the same month costs a
number that never meant anything.

The shape stays `{major, minor}`. Only the counting is deferred. `major`
already does real work -- `Document::from_json` refuses a document whose major
differs -- and nothing in the tree reads `minor` for behaviour, which is why
this reset changes exactly two lines of code and two of witness.

## What is not being relaxed

**The schema is not free to change quietly.** That was never the version's job.
The two witnesses under `docs/schema/` are what make a change visible: every
one of them moves, and `make schema-bless` has to be run deliberately, so a
schema change is a reviewable diff in the same commit as the code that caused
it (decision 0020). That mechanism is untouched and remains the thing to be
careful about.

The rest of section 2's rules also stand as they are:

- A consumer rejects a document whose **major** differs from its own.
- A consumer rejects any document containing a **field it does not recognise**.
  Silent field-dropping stays forbidden -- and with `minor` pinned, this is the
  rule that actually protects anybody, since a build without `on_unmanage`
  refuses a document carrying it rather than ignoring the flag.

That second point is worth stating plainly: pinning the version makes the
unknown-field rule *more* load-bearing, not less.

## What happens at the release

`minor` starts counting from the shipped schema. The first release is 1.0 and
the first field added after it makes 1.1. Everything between now and then is
1.0, including the several bumps this decision reverses.

Nothing needs to be remembered for that to work, which is the point of choosing
now rather than later: there is no list of deferred bumps to replay, because
the version was never carrying information that mattered.
