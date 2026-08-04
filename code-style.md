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
verdict and sections 4 through 8 -- is this project's own, and is not in
the source.

Vendored or generated sources are exempt — they keep whatever their
generator or upstream produces. Nothing is vendored yet; when something is,
say so here.

## The three rules

1. **`snake_case`, not `camelCase`,** for identifiers this project defines.
2. **Tabs for indentation, spaces for alignment.**
3. **Lowercase filenames,** unless a tool demands otherwise.

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
fences are space-indented by specification), **Go** (`gofmt` emits tabs
natively), and **vendored, generated or attic sources**, which keep whatever
their upstream or generator produced.

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
**ASCII**. Write `--` where prose would use an em dash. Markdown documents
are the exception and may use typographic punctuation — `project.md` and
`netcfgd-design.md` already do throughout.

This is a rule about the text this project writes, not about the data it
handles. An SSID is 0..32 arbitrary octets and is explicitly not guaranteed
to be UTF-8 (§2.1); a hostname from a DHCP lease is whatever the server
sent. Parsers and the model treat those as bytes and must not assume
otherwise. The two rules do not conflict: one governs the repository, the
other governs the wire.

## 6. Modules and comments

Every module opens with a `//!` doc comment stating its single
responsibility. If that comment needs two sentences joined by "and", the
module wants splitting.

This has teeth here rather than being a nicety. §5 requires
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

Precise and short. What changed and why, in as few words as do the job.

The subject carries the crate or adapter it touches, first and followed by a
colon, then a word from the shared set saying what the change does:

    netcfgd-plan: fix the ordering edge for a renamed link
    nm: rework the containment check as one pass

`git log --grep '^netcfgd-plan:'` then answers what has happened to the
planner without a path list, and keeps answering after files move.

- **The message ends at its real content.** No trailers, no sign-offs, no
  tooling or assistant attribution.
- **No docs-only commits.** Documentation rides along with the code commit
  it describes; folding an accumulated session's findings back into
  `project.md` is the standing exception.
- **Nothing under `/run` or `target/` is ever committed,** and neither is
  anything containing real secret material -- not in fixtures, not in test
  data, not "temporarily".

There is deliberately no subject format, column limit or body shape here.
Those were stated once, were never asked for, and produced commit bodies
averaging tens of lines across every sibling project.
## See also

- **`project.md` §9** — working in this repo: build and CI conventions, and
  the rules above in brief.
- **`project.md` §1** — the hard constraints. Constraint 4 (`unsafe`) and
  constraint 8 (size budgets as CI gates from commit 1) are the two that
  shape day-to-day code most.
- **`netcfgd-design.md` §12** — why Rust, and the security posture that
  follows from a daemon holding `CAP_NET_ADMIN`.
