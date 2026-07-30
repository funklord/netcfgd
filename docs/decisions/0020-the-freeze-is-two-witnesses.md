# 0020: the freeze is two witnesses, not a promise

Status: accepted
Date: 2026-07-30
Milestone: M4

## Context

M4's row ends "**Model, document schema and socket API freeze here.**"
Project.md section 8 says why the freeze is scheduled before the adapters
exist: "the model freezes before any adapter exists, so no adapter can shape
it."

A freeze that is only written down is not a freeze. The changes that break a
schema do not look like breaking changes in a diff:

- a field renamed while tidying;
- an enum variant reordered so the list reads better;
- a `skip_serializing_if` added, which removes a field from every document
  where the value happens to be the default;
- a type widened from `u16` to `u32`, which is source-compatible and changes
  nothing until somebody's parser rejects a larger number.

Each is a one-line diff that a reviewer approves. Each breaks a consumer.

## Decision

**The frozen surface is written down as data and checked, not described in
prose.** Two witnesses under `docs/schema/`:

- `document.json` -- one document with every field populated and every enum
  variant present, canonically serialised.
- `socket.json` -- one of every request, response and event, in the
  newline-delimited framing the socket actually uses.

A test in each crate rebuilds its witness and compares. Any change to either
wire form moves those bytes and fails the build. `make schema-bless` rewrites
them, and the commit has to say whether the change is a minor bump or a major
one. Same mechanism as `size-budget.txt`, for the same reason: a limit that
moves silently is not a limit.

**The witnesses are written by hand.** A generated one would drift in step
with the thing it is meant to pin. Writing it out is also what forces somebody
adding a field to look at every other field, which is the point at which most
schema mistakes are still cheap.

### Two stages, and the first is the useful one

Adding a field to a model struct does not merely change the JSON -- it stops
the witness compiling, because every struct literal in it lists every field.
The author has to open the witness and decide what the new field's value is
before they can see the JSON diff at all.

That ordering matters. The compile error arrives while they are still thinking
about the field; the JSON diff arrives when they are trying to get the build
green. Verified both stages by adding a field and watching each fire in turn.

### What counts as which bump

| Change | Bump | Effect on a reader |
|---|---|---|
| A field added, with a default | minor | old readers ignore it |
| A request or response added | minor | old clients never send it |
| A field renamed or removed | **major** | the document is refused outright |
| An enum variant renamed | **major** | same |
| A type narrowed or widened | **major** | may parse, may not; worse either way |
| A `skip_serializing_if` added | **major** | a field silently disappears |

`Document::from_json` refuses a document whose major differs, so a major bump
is not a soft deprecation -- it is every consumer stopping at once. The table
is in the record rather than only in the test so that the answer to "is this
allowed?" does not require reading Rust.

### The socket is the stricter half

The document schema is read by netcfgd. The socket is read by whatever anybody
wrote against it, and there is no handshake that would let an old client be
told it is old -- `Hello` reports versions, and a client that never asks finds
out by failing. So the socket witness pins the *framing* as well as the
content: one JSON object per line, checked, because a message containing a
newline would frame as two and desynchronise a stream rather than error.

## Consequences

**The schema found a defect the moment it was written down.** `TunnelConfig`
had a field called `kind`, and `InterfaceKind` is serialised with an internal
tag also called `kind` -- so a tunnel serialised with the field twice, which
serde writes happily and refuses to read back. Nothing had caught it because
nothing had ever serialised a tunnel and read it back; the witness does both
by construction. The field is `mode` now. Had the freeze been a paragraph, that
would have been frozen in.

**Adding a model field is now a three-file change**: the type, the witness, and
`docs/schema/document.json`. That is friction on purpose, and it is the
cheapest of the three that matters -- the witness is where somebody reads the
field next to its neighbours and notices it does not belong.

**The witnesses are large** -- five thousand lines for the document -- and they
are meant to be read as a diff rather than as a file. Nobody should open
`document.json` to learn the schema; the types are the documentation and this
is the tripwire.

**M4 is done.** What remains for M5 onward builds on a surface that cannot move
without saying so.

## Alternatives considered

**A JSON Schema document.** Rejected: it is a second description of the model
that has to be kept in step by hand, and the failure mode is the schema and the
code disagreeing while both look maintained. A witness is generated *from* the
types, so it cannot describe something the code does not do.

**`cargo public-api` or a similar API-diff tool.** Rejected on constraint 3 --
it is a build dependency, and it pins the Rust API rather than the wire format.
The Rust API is not what a consumer sees; two different Rust shapes can produce
identical JSON, and identical Rust can produce different JSON after one serde
attribute.

**Version every message and support both.** Rejected as premature. There are no
consumers yet whose upgrade has to be staged, and building the machinery for
that before anybody needs it is how a protocol acquires compatibility shims
nobody can remove. The freeze is what makes staged upgrades unnecessary for
now; if it ever becomes necessary, it will be a decision with a real case
behind it.

**Freeze only the document, not the socket.** Tempting, since the socket has
fewer consumers today. Rejected because that is exactly backwards: the document
is read by netcfgd, which is upgraded together with the schema, while the
socket is read by tooling that is not.
