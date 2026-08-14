<!-- The three rules and their detail are copied from
     ~/.claude/guidelines/code-style.md -- the source. Keep in sync; fix
     drift the moment you notice it. -->

# code-style.md

Code style for this project. Applies to every crate in the workspace — the
pure core (`netcfgd-model`, `netcfgd-compile`, `netcfgd-plan`), the crates
that touch the kernel (`netcfgd-sys`, `netcfgd-observe`,
`netcfgd-apply`), the binaries (`netcfgd`, `ncfg`), the backends and the
adapters alike — **and to `client/` in C and `gui/` in C++**, which are not
crates and are not exempt. Those two are where several of the rules below
actually bite, because Rust supplies for free what C and C++ do not. `project.md` §9 states the rules in brief and points here
for the detail; where the two ever disagree, project.md wins.

**Above both sits the global source**, `~/.claude/guidelines/code-style.md`,
which applies to every private project. Where this file or `project.md`
disagrees with it, that is **drift to fix, not a local override**. A genuine
divergence needs a technical reason and is raised rather than decided in
passing -- and when a conflict between the three actually comes up, stop and
ask instead of picking a winner.

Everything specific to Rust and to this project -- section 2's `rustfmt`
verdict and sections 4 and 6 through 8 -- is this project's own, and is not
in the source. The numbering skips 5 deliberately: that section was *Line
length*, withdrawn as a rule nobody had asked for, and the sections after it
kept their numbers so that the references `project.md` and the decision
records already carry keep resolving.

Vendored or generated sources are exempt — they keep whatever their
generator or upstream produces. Nothing is vendored yet; when something is,
say so here.

## The three rules

1. **`snake_case`, not `camelCase`,** for identifiers this project defines.
2. **Tabs for indentation, spaces for alignment.**
3. **Lowercase filenames,** unless a tool demands otherwise.

Everything below is these three rules in detail, plus the exceptions that are
already settled. **An exception not listed is not yet settled**: raise it
rather than deciding it in passing.

## 1. Naming

Rust already gets most of rule 1 for free: `non_snake_case` and
`non_camel_case_types` are on by default, so functions, variables, modules
and fields are `snake_case`, types and variants are `PascalCase`, constants
are `SCREAMING_SNAKE_CASE`, and none of that needs restating. What the
lints do not cover is the part that matters:

- **Crate names are `netcfgd-`-prefixed and kebab-cased** in `Cargo.toml`
  (`netcfgd-model`), which Rust reads back as `netcfgd_model` in a `use`
  path. The two spellings of one crate are the toolchain's doing, not a
  choice; do not invent a third by naming the directory differently from the
  package.
- **No abbreviations that are not already vocabulary.** `observed`, not
  `obs`; `interface`, not `iff`. This is stricter than ordinary Rust taste
  for a specific reason: this project's struct field names *are* its JSON
  field names *are* its `/run` file names *are* the dotted paths in a
  `Reason` (§4). An abbreviation invented inside a struct definition ends up
  in `ncfg explain` output and then in somebody's grep, where it can no
  longer be renamed. Names in `netcfgd-model` are a public interface even
  before the schema freezes at M4.
- **One word per concept, everywhere.** `desired` and `observed` are the
  clearest case: the same word in the type name, the `/run` path, the CLI
  subcommand and the documentation, and no synonym anywhere. A synonym
  introduced for variety is a second concept as far as any reader is
  concerned. `docs/decisions/0005-state-vocabulary.md` settles which pair,
  and rules out carrying both as aliases.
- **Prefer the plain descriptive name over the redundant one.** The type a
  planner returns is `Plan`, not `PlanStruct` or `PlanResult`;
  `netcfgd_plan::Plan` already reads correctly at the call site, and
  stuttering only shows up once someone imports it.

**A toolkit whose own API is `camelCase` does not pull your names across.**
Call the foreign API exactly as it is spelled -- `setParent`, `addWidget`,
`setEnabled` -- because that is not a violation, it is the API's name. But
names *you* introduce stay `snake_case` on the same line. This is Rust's rule
for free and C++'s not at all, so `gui/` is where it has to be held
deliberately: `ncfg_apply_dialog::build_consent` calling
`consent_box->setVisible` is both halves correct, and neither half should
drift toward the other.

### Prefixes, and visibility

Prefixes keep this project's symbols from colliding with a library's, so
they follow **visibility** rather than a mechanical rule:

- **Anything with more than small visibility carries the project prefix** --
  the public API, and anything a linker or importer outside its own module
  can reach.
- **Module-private symbols are left unprefixed**, so that the absence of a
  prefix reads as "this does not leave the module."

Rust settles the middle case by itself: `pub` and the module tree decide what
escapes, and the crate name is already the prefix at every call site. **C and
C++ do not**, which is why this section exists now that `client/` and `gui/`
are here. A symbol that is internal by intent but still reaches the linker --
cross-file within a library, not `static`, not part of the API -- is not
private for this purpose. Prefix it. `client/` already does: everything it
exports is `ncfg_client_*` or `ncfg_json_*`, and `gui/` names its own types
`ncfg_apply_dialog` and the like.

**A deliberate parallel copy of a function in two libraries needs a distinct
name**, not the same name in both on the assumption that nothing will ever
link both sides. That assumption fails later, at a call site that changed
nothing, and names files you did not touch.

## 2. Indentation and alignment

Indent structural nesting with **tab** characters, one tab per level. When
lining up continuation or aligned tokens *within* a line, use **spaces**
after the indent tabs.

The point of the split: alignment is expressed relative to the shared
leading tabs, so it survives at any tab width, and no tab width is
prescribed anywhere. The viewer decides. If two lines are short enough to
merge rather than align, merge them.

In practice Rust reaches for alignment far less often than C does, because
`rustfmt`'s default block style breaks a long signature onto its own
indented lines instead of lining arguments up under the open paren:

```rust
fn plan_for(
→   desired: &Document,
→   observed: &Observed,
→   opts: &Options,
) -> Result<Plan, Error> {
→   if desired.interfaces.is_empty() {
→   →   return Ok(Plan::empty());
→   }
→   Ok(Plan { actions: collect_actions(desired, observed, opts)? })
}
```

(`→` marks a tab.) Every leading column there is a tab and nothing is
aligned to a paren, which is the shape to aim for.

**Never mix tabs and spaces within the indent itself.** Tabs come first and
spaces come after; the reverse, or an alternation between them, is exactly
what breaks at a different tab width -- which is the one thing the split
exists to prevent. In the nine Python scripts under `tests/live/` and
`tools/` it is worse than cosmetic: a space *before* a tab in leading
whitespace raises `TabError`, so a file that looks right refuses to run.
Continuation lines inside brackets are not indentation-significant there at
all, which is why PEP 8's preference for spaces does not reach this rule.

### rustfmt *is* used here — unlike the sibling projects

The C and Python projects next door ban their formatters outright, because
`clang-format` and `black` rewrite tabs to spaces unconditionally and cannot
be configured out of it. That reasoning does not carry over. `rustfmt` has a
stable `hard_tabs` option, and with the default `indent_style = "Block"`
there is no visual alignment for it to fight over. The rule survives the
tool, so the tool stays.

`rustfmt.toml` at the workspace root holds exactly the settings that follow
from the rules above and nothing decorative:

```toml
hard_tabs     = true
max_width     = 100
newline_style = "Unix"
```

`cargo fmt --check` is a CI gate, alongside `cargo clippy -- -D warnings`.
Run both before committing. If `hard_tabs` is ever dropped from the config,
the whole tree converts to spaces on the next format and the diff will bury
whatever change it rode in on — treat that file as load-bearing.

### Settled exceptions to the tab rule

Divergence needs a technical reason. These are accepted and need no
discussion: **Makefile recipe lines** (`make` requires a literal tab, so they
are compliant by construction), **YAML** (the spec forbids tabs for
indentation outright — use spaces), **Markdown** (list continuation and code
fences are space-indented by specification), **Debian packaging files** (see
below), **Go** (`gofmt` emits tabs natively), and **vendored, generated or
attic sources**, which keep whatever their upstream or generator produced.

**The two halves of `debian/` are exempt for different reasons**, and both
were measured against dpkg rather than read off the manual.
`debian/changelog` has a fixed layout that a tab is simply not part of:
`dpkg-parsechangelog` calls a tab-indented change line "unrecognized", and
loses the trailer outright if a tab precedes `--`. A deb822 continuation in
`control` or `copyright` is the opposite case — `deb822(5)` allows a leading
SPACE *or* TAB and dpkg round-trips either, but that leading whitespace is
field *syntax* rather than indentation, so the rule has nothing to say about
it and everything past it is alignment.

Anything else that seems to need spaces is **not settled by not being
mentioned**: raise it, get it settled, and add it here.

### No formatter for `client/` and `gui/`

`clang-format` is **not run here, not even ad hoc on a single file**, for the
reason the sibling C projects recorded: it rewrites tabs to spaces
unconditionally and cannot be configured out of it. That is a configuration
gap, which is disqualifying rather than something to work around — the
failure mode is a silent conversion of files that were already correct,
found later as a reverted commit rather than as an error.

This is the same evaluation `rustfmt` passed and it fails: the rule has to
survive the tool, and here it does not.

Naming and filename rules are review items, not automated ones.

## 3. Filenames

Lowercase for everything this project names itself.

- Rust sources are `snake_case.rs`, matching the module path:
  `desired_state.rs`, not `DesiredState.rs` or `desired-state.rs`.
- Markdown and other prose files are kebab-cased: `code-style.md`,
  `netcfgd-design.md`.
- Config fixtures and test data follow the thing they describe.

The exception is a name a tool will not accept lowercased or in another
shape: `Cargo.toml`, `Cargo.lock`, `README.md`, `LICENSE`, `Makefile`.

## 4. ASCII only in source

Source, comments, doc comments, test fixtures and commit messages are
**ASCII**. Write `--` where prose would use an em dash. Three things are
excepted, and they are the rule's shape rather than holes in it:

- **Documentation.** Markdown may use typographic punctuation — `project.md`
  and `netcfgd-design.md` already do throughout, and so does this file.
- **User-facing text a program prints.** A glyph in a `gui/` label or a tick
  in `ncfg` output is output, not prose, and the rule has nothing to say
  about it.
- **Anything that genuinely requires Unicode.** `tests/determinism/` carries
  a deliberately non-ASCII SSID, which is the entire point of the fixture:
  a document that survives three architectures unchanged has to survive them
  with its multi-byte characters intact.

This is a rule about the text this project writes, not about the data it
handles. An SSID is 0..32 arbitrary octets and is explicitly not guaranteed
to be UTF-8 (§2.1); a hostname from a DHCP lease is whatever the server
sent. Parsers and the model treat those as bytes and must not assume
otherwise. The two rules do not conflict: one governs the repository, the
other governs the wire.

The rule is enforced, not merely stated: `ascii_only = true` in
`.style-gate.toml`, checked by `make style` over the 209 files the gate
sees. **In the two languages it can lex, it means ASCII outside string and
character literals** — the nine Python scripts under `tests/live/` and
`tools/`, read with `tokenize`, and the C of `client/` and the C++ of `gui/`,
read with a scanner written for the purpose because nothing in the standard
library lexes them. That is what makes the UI exception above enforceable
rather than merely stated: a glyph inside a `gui/` string literal passes and
an em dash in the comment above it does not.

Rust and everything else get a whole-file byte check, there being no lexer
here for them, and so does a file in either lexed language that will not
parse: a file nobody can read is not a file that has been cleared. Markdown
is out of the check entirely, which is the documentation exception.

That distinction is the rule above expressed mechanically — the text this
project writes about itself against the data it handles — and it exists
because a byte scan could not draw it. A sibling project that prints two
status ticks had to switch the check off for a whole file to keep them,
which switched it off for that file's comments as well, and an em dash duly
arrived in one. **An exception wider than its reason is how a rule stops
being enforced.**

## 6. Modules and comments

Every module opens with a `//!` doc comment stating its single
responsibility. If that comment needs two sentences joined by "and", the
module wants splitting.

This has teeth here rather than being a nicety. `project.md` §5 requires
`netcfgd-model`, `netcfgd-compile` and `netcfgd-plan` to be pure and
hardware-free, which is what makes the entire planner unit-testable against
fixtures. A module whose stated responsibility has quietly grown a second
half is how I/O first appears in a crate that is supposed to have none.

Comments explain **why**. The what is in the code and stays there; a comment
restating a line is one more thing to keep true. Comment density should
match the surrounding file. The places worth a paragraph are the ones where
the obvious implementation is wrong: ordering edges in the planner (§4),
anything touching `rtm_protocol` and object ownership (§2.3), and every
`unsafe` block.

## 7. `unsafe`

`#![forbid(unsafe_code)]` is the **first line** of every crate root, written
identically in each, so its absence is visible at a glance rather than by
grepping. `netcfgd-sys` is the sole exception (§1.4) and says so in its
crate-level doc comment, immediately above the `#![allow(unsafe_code)]` that
replaces it.

Inside that one crate, every `unsafe` block carries a `// SAFETY:` comment
naming the invariant that makes it sound and what upholds it. A block
without one does not merit review time.

## 8. Commit messages

Kernel format. See `~/.claude/guidelines/build-and-commit.md` for the full
statement; what is specific here is the subsystem name.

    netcfgd-plan: fix the ordering edge for a renamed link
    adapters/nm: rework the containment check as one pass

The crate or adapter comes first, followed by a colon, with a slash for
nesting. `git log --grep '^netcfgd-plan:'` then answers what has happened to
the planner without naming paths, and keeps answering after files move.

Subject at 75 columns, imperative mood, no trailing period. The body
explains why rather than what, wrapped at 75. Length is not a constraint:
this document can be deleted, and the log cannot, so a message that carries
the reasoning behind a decision is doing the job the design docs would
otherwise have to.

Trailers at the end -- `Fixes:`, `Reported-by:`, `Reviewed-by:`,
`Tested-by:`, `Signed-off-by:`. The one prohibition is generator
attribution: a tool is not an author and does not sign anything.

- **Nothing under `/run` or `target/` is ever committed,** and neither is
  anything containing real secret material -- not in fixtures, not in test
  data, not "temporarily".

The commit-msg hook is `tools/hooks/commit-msg`, installed with `make hooks`.
It rejects generator attribution, a subject over 75 columns, and body prose
over 75 columns. It lives in the tree rather than only in `.git/hooks` so
that it is reviewable and survives a clone; the copy that runs is installed
from it.

The body limit was stated long before anything checked it, and only the
subject was checked -- so a body line at 76 columns went through while a
subject at 76 was refused.

What it deliberately does not reject, in three groups.

**Three names are spared**, so a message may say where the shared tooling
comes from: the directory `.claude`, the file `CLAUDE.md`, and
`claude-guidelines`, the repository the guidelines live in. The ban is on
crediting a generator and none of the three is a spelling of that. Only the
names are neutralised, never the token around them -- a vendor word at the
end of a path under the tree is still refused.

**What git is about to discard**: comment lines, and the diff that
`git commit -v` puts below the scissors line. Reading those refused commits
over text that never reaches the message -- the hook's own diff contains its
own pattern list, so it rejected every commit that edited it.

**Three shapes the length check exempts**, each because wrapping it is the
actual mistake rather than a concession: a *trailer*, since git parses the
block a line at a time and a broken `Link:` stops being a trailer at all; a
line holding a *url*, which no longer works once it is split; and an
*indented* line, which is how a message quotes a compiler error or a stack
trace, where reflowing what you are quoting corrupts the one thing it was
included for. It cannot tell prose opening `Note:` from a trailer, so it
forgives that -- the wrong way round would refuse a real trailer, and that
is the expensive error.

## See also

- **`project.md` §9** — working in this repo: build and CI conventions, and
  the rules above in brief.
- **`project.md` §1** — the hard constraints. Constraint 4 (`unsafe`) and
  constraint 8 (size budgets as CI gates from commit 1) are the two that
  shape day-to-day code most.
- **`netcfgd-design.md` §12** — why Rust, and the security posture that
  follows from a daemon holding `CAP_NET_ADMIN`.
