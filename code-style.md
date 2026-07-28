# code-style.md

Code style for this project. Applies to every crate in the workspace — the
pure core (`netcfgd-model`, `netcfgd-compile`, `netcfgd-plan`), the crates
that touch the kernel (`netcfgd-netlink`, `netcfgd-observe`,
`netcfgd-apply`), the binaries (`netcfgd`, `ncfg`), the backends and the
adapters alike. `project.md` §9 states the rules in brief and points here
for the detail; where the two ever disagree, project.md wins.

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

## 5. Line length

Soft 100 columns, and `max_width` is set to match so `rustfmt` agrees. Do
not sacrifice clarity to it — a 104-column line that reads as one thought
beats a wrapped one that does not. Commit message bodies wrap at 72, which
is a different limit for a different reason (`git log` indents them).

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
grepping. `netcfgd-netlink` is the sole exception (§1.4) and says so in its
crate-level doc comment, immediately above the `#![allow(unsafe_code)]` that
replaces it.

Inside that one crate, every `unsafe` block carries a `// SAFETY:` comment
naming the invariant that makes it sound and what upholds it. A block
without one does not merit review time.

## 8. Commit messages

Modelled on the sibling projects, because the history there has turned out
to be worth reading a year later.

- **Subject line: capitalised, imperative, no trailing period,** 72 columns
  or fewer. "Derive the pacer's rate from the link table", not "fix stuff"
  and not "feat(plan): ...". No conventional-commit prefixes, no type tags,
  no ticket numbers, no emoji.
- **Body: prose, wrapped at 72,** explaining *why* the change is right and
  what was learned making it — a wrong turn taken and reverted, a test that
  passed for the wrong reason, a number that turned out to be guessed.
  Bullet lists are fine inside it; a body that is *only* a bullet list of
  what changed is not, since `git diff` already says that.
- **The message ends at its real content.** No trailers, no sign-offs, no
  tooling or assistant attribution (`Co-Authored-By:` lines for anything
  that is not a person, `Generated with ...` footers, and the like). The
  author field carries the attribution git needs.
- **No docs-only commits.** Documentation changes ride along with the code
  commit they describe. Folding an accumulated session's findings back into
  `project.md` is the standing exception, and reads as its own commit.
- **Nothing under `/run` or `target/` is ever committed,** and neither is
  anything containing real secret material — not in fixtures, not in test
  data, not "temporarily". §2 makes the desired-state document
  secret-free by construction; the repository holds to the same rule.

Changing any of the above is a convention change: raise it rather than
adjusting the default in passing.

## See also

- **`project.md` §9** — working in this repo: build and CI conventions, and
  the rules above in brief.
- **`project.md` §1** — the hard constraints. Constraint 4 (`unsafe`) and
  constraint 8 (size budgets as CI gates from commit 1) are the two that
  shape day-to-day code most.
- **`netcfgd-design.md` §12** — why Rust, and the security posture that
  follows from a daemon holding `CAP_NET_ADMIN`.
