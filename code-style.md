<!-- Copied from ~/.claude/guidelines/code-style.md by tool/sync.py.
     Edit the source, not this part: this project's own rules follow
     the end-of-copy line below. -->

# code-style.md

Code style for private projects. This file is the **source**. Every private
project except the one holding it carries a copy at its repo root, written
by `tool/sync.py` -- see *Keeping the copies in sync* at the end.

Vendored submodules, generated sources and attic/historical material are
exempt: they keep whatever their upstream or generator produces. Each
project names its own exempt paths in its part of the file.

## The three rules

1. **`snake_case`, not `camelCase`,** for identifiers this project defines.
2. **Tabs for indentation, spaces for alignment.**
3. **Lowercase filenames,** unless a tool demands otherwise.

Everything below is these three rules in detail, plus the exceptions that
are already settled. An exception not listed here is not yet settled: raise
it rather than deciding in passing.

## 1. Naming

`snake_case` for functions, variables, type names and fields.

This holds **even inside a toolkit whose own API is `camelCase`**. Call the
foreign API exactly as it is spelled (`setParent`, `addWidget`) -- that is
the API's name, not a violation. But names *you* introduce stay
`snake_case`; do not let the surrounding convention pull them across.

- **Name the thing, not its category**: `plan`, not `plan_struct` or
  `plan_result`.
- **No abbreviations that are not already vocabulary.** `observed`, not
  `obs`; `interface`, not `iff`. This matters most where an internal name
  escapes into something you cannot rename later -- a wire format, a config
  key, a CLI output, an on-disk path.
- **One word per concept, everywhere** -- the same word in the type name,
  the file path, the subcommand and the documentation. A synonym introduced
  for variety reads as a second concept.

### Prefixes, and visibility

Prefixes keep this project's symbols from colliding with a library's, so
they follow **visibility**, and the choice is judgement rather than a
mechanical rule:

- **Anything with more than small visibility carries the project prefix**
  -- the public API, and anything a linker or importer outside its own
  module can reach.
- **Module-private symbols are left unprefixed**, so that the absence of a
  prefix reads as "this does not leave the module."

The middle case decides itself on link safety, not taste. A symbol internal
by intent but still reaching the linker -- cross-file within a library, not
`static`, not part of the API -- is *not* private for this purpose: prefix
it. A deliberate parallel copy of a function in two libraries needs a
**distinct** name; the assumption that nothing will ever link both sides
fails later, at a call site that changed nothing, and names files you did
not touch.

Where a language enforces its own scheme, accept it, and say in the
project's part of this file that the toolchain is doing it:

- **Rust** -- `non_snake_case` and `non_camel_case_types` are on by
  default, so types are `PascalCase` and constants `SCREAMING_SNAKE_CASE`
  -- the toolchain's, not a choice. Package systems that demand kebab-case
  (Cargo crates, Debian packages) read back with their own spelling; do not
  invent a third by naming the directory differently from the package.
- **Python** -- a leading underscore (`_name`) is the language's private
  marker and stands in for "unprefixed" above.

## 2. Indentation and alignment

Indent structural nesting with **tab** characters, one tab per level. When
lining up tokens *within* a line -- continuation parameters under an open
paren, a block comment's `*` column, an aligned trailing comment -- use
**spaces**, after the indent tabs. Alignment is then relative to the shared
leading tabs, so it survives at any tab width. No tab width is prescribed;
the viewer decides.

```c
int thing_do(thing_t *thing, const char *name, size_t name_len,
              uint8_t *out, size_t out_cap) {
>---if (!thing) return ERR_MALFORMED;
>---return thing_write(thing, name, name_len, out, out_cap,
>---                    THING_DEFAULT_FLAGS);
}
```

(`>---` marks a tab; everything lining up under `(` is spaces.)

Never mix tabs and spaces *within* the indent itself. Tabs come first and
spaces after; the reverse, or an alternation, breaks at a different tab
width -- and in Python it is a syntax error.

### Settled exceptions

Divergence needs a technical reason. These are accepted:

- **Makefile recipe lines** -- `make` requires a literal tab. Compliant by
  construction.
- **YAML** -- the spec forbids tabs for indentation. Use spaces.
- **Markdown** -- list continuation and code fences are space-indented by
  specification. Exempt.
- **Debian packaging files** -- exempt, for two reasons measured against
  dpkg. `debian/changelog` has a fixed layout with no tab in it:
  `dpkg-parsechangelog` calls a tab-indented change line "unrecognized"
  and loses the trailer if a tab precedes `--`. A deb822 continuation in
  `control` or `copyright` may lead with a space *or* a tab, but that
  whitespace is field syntax rather than indentation, and everything past
  it is alignment.
- **Go** -- `gofmt` emits tabs natively. Compliant already.
- **Vendored, generated and attic sources** -- exempt, per the header.

**Python**: PEP 8 prefers spaces, but the language's only hard rule is that
indentation must not be *ambiguous*, and tabs-then-spaces is unambiguous at
every tab width. Continuation lines inside brackets are not
indentation-significant at all. Never a space *before* a tab in leading
whitespace -- that is what raises `TabError`.

Anything else that seems to need spaces: signal it to the list in
`claude-guidelines`' `project.md`, follow the rule meanwhile, and it is
settled here in a pass rather than in whichever project met it first.

## 3. Filenames

**Lowercase, always**, for everything the project names itself:
`main_window.cpp`, not `MainWindow.cpp`.

**The separator follows what the name binds to**, which is a technical
difference rather than taste:

- **`snake_case` where the filename becomes an identifier** -- a source
  file, a header, a module. `desired_state.rs` *is* the module
  `desired_state`, and `desired-state.rs` cannot be a module at all, a
  hyphen not being legal in a Rust path; Python imports are the same. That
  is the language's requirement, and not negotiable where it applies.
- **`kebab-case` for prose** -- documentation, design notes, decision
  records. Nothing imports `code-style.md`, so no identifier is at stake,
  and kebab-case is what markdown and URLs settled on. (When this rule said
  `snake_case` for documentation too, 174 of 197 markdown names across the
  workspace were already kebab-case.)

Settled exceptions:

- **Names a tool will not accept lowercased** -- `Makefile`,
  `CMakeLists.txt`, `AndroidManifest.xml`, `Dockerfile`, `Cargo.toml`.
- **Root files with an established convention** -- `README.md`, `LICENSE`,
  `CHANGELOG.md`, `AUTHORS`, `VERSION`. The last is this workspace's own: a
  project that packages or ships a version tracks one, and the build reads
  it for the package version and for what the program prints, so the
  number lives in one place. `claude-guidelines` packages nothing and has
  none.
- **Package-system spellings** -- kebab-case where Cargo or Debian require
  it, which is the spelling prose uses, so a crate directory and the design
  note beside it agree by construction.

### Singular, unless somebody else standardised the plural

**Prefer the singular for a directory this project names itself**:
`helper/`, `doc/`, `fixture/`. The name says what kind of thing lives
there, not how many, and should not have to change when the count does.

Two exceptions, and they are not equal -- the same shape as the lowercase
rule, which yields first to `Makefile` because make will read nothing else,
and only then to `README.md` because the world settled it.

**First: a name a tool requires is not a name we choose.** It outranks the
singular as it outranks lowercase, needs no measurement, and the test is
whether something breaks when the name changes. It is open-ended: a tool
met tomorrow that demands a name gets the same answer, whether the name is
plural, singular, capitalised or none of those. Present here: **Cargo**
looks for `tests/`, `examples/` and `benches/`, and `cargo-fuzz` for
`fuzz_targets/`; **GitHub** requires `.github/workflows/`; **git** keeps
`hooks/`, hence `tool/hooks/`. **A foreign package's directory names are
the same exception one layer out**: the Android SDK's `platform-tools/` and
`build-tools/` are the SDK's spelling. A word-boundary rewrite of `tools/`
once reached into `platform-tools/`, the hyphen being a boundary, and every
adb target in four projects pointed at a binary that was not there -- so a
sweep skips compound names it does not own. Package-system spellings (Cargo
crates, Debian packages) under *Filenames* above are this same carve-out.

**Second: a plural an ecosystem has settled** -- a convention rather than a
requirement: nothing breaks, but a reader would be surprised. Cargo
workspaces keep members in `crates/`. **These need measuring**, and the
project's part of this file names what it measured against, so the next
reader does not reopen it.

Say which kind is being claimed: confusing them lands on whoever renames a
directory that looked like a convention and finds the build broken. And an
inventory name in `harmonization.md` moves only when its owner says so, in
a deliberate pass with each project's gates run against the result -- as
`tools/`, `docs/` and `docs/decisions/` became `tool/`, `doc/` and
`doc/decision/` -- never as a side effect of a style rule.

## ASCII in source

Source and comments are ASCII. Write `--` where prose would use an em dash,
and "section" for a section sign.

This governs **the text the repository writes about itself**, not the data
the software handles. Three exceptions, which are the rule's shape rather
than holes in it:

- **Documentation.** Markdown may use typographic punctuation.
- **User-facing text in UI software.** A tick a program prints is output,
  not prose -- `GREEN('gpg ')` is correct as it stands.
- **Anything that genuinely requires Unicode**: a fixture for a UTF-8
  parser, a terminal emulator's character tables, a font tool.

Where a project needs the rule enforced, `ascii_only` in `.style-gate.toml`
turns it on. In Python and in C/C++ it enforces exactly that shape -- ASCII
outside string literals, Unicode allowed inside -- reading Python with
`tokenize` and C and C++ with a scanner written for the purpose. Every
other language gets a whole-file byte check, and so does a file in those
two that will not lex: a file nobody can parse is not a file that has been
cleared.

**An exception wider than its reason is how a rule stops being enforced.**
The check was once whole-file for everyone, so a project printing two
status ticks switched it off, and an em dash arrived in a comment; in a Qt
tree that kept it off for its toolbar glyphs, 854 of 1114 non-ASCII
characters turned out to be prose in comments.

## Formatters

A formatter is allowed **only if it can be configured to honour the three
rules completely**. Configuration gaps are disqualifying: a formatter that
gets indentation right and alignment wrong rewrites the tree on somebody's
next save. So the decision is per tool, per project, and a real evaluation:

- If it can be made to comply, use it, and commit the config with a comment
  saying which setting is load-bearing and what happens without it.
- If it cannot, do not run it -- **not even ad hoc on a single file**. The
  failure is a silent conversion of files that were already correct,
  found later as a reverted commit rather than an error.
- If no existing tool fits and the rule is worth mechanising, write our
  own. A checker that only gates indentation is worth more than a formatter
  that reflows everything.

**Record the decision and the finding that produced it** in the project's
part of this file -- which tool, what failed, what would change the answer.
A verdict without its evidence gets re-litigated, and a tool that improves
later is never reconsidered because nobody remembers what was wrong with
it.

Naming and filename rules are review items, not automated ones.

## Precedence

Three layers, and they are not equals:

1. **The global guidelines** (`~/.claude/CLAUDE.md` and the files it
   imports) -- the source, and they win.
2. **The project's `project.md`** -- project-specific design and
   conventions.
3. **The project's `code-style.md`** -- this file, copied, and the
   project's own part after it.

A project file that disagrees with the source is **drift, not an
override**: fix it. A project that genuinely needs to diverge needs a
technical reason, and that is not a decision to make while working on
something else -- signal it to the list in `claude-guidelines`'
`project.md` and keep following the source meanwhile.

**When a conflict between layers actually comes up, stop and ask.** Do not
silently pick a winner, even the global one.

This precedence rule lives here and in the global guidelines only. It does
not belong in a `project.md`.

## Keeping the copies in sync

Each private project keeps `code-style.md` at its root, in two parts: this
source, verbatim, under a header naming it; then, after a line marking the
end of the copy, **the project's own part**, holding only what is genuinely
its own -- its exempt paths, formatter verdicts, language-specific notes
and tooling commands, under its own headings. `claude-guidelines` is the
exception: it holds the source at `guidelines/code-style.md`, and its root
file points here.

**`tool/sync.py` writes the copied part and never touches the project's
part**, the same way it spreads the gate. So a copy cannot drift, and a
project that wants a rule to read differently changes the source, through
the signal list, rather than its copy. Until 2026-11-20 copies were adapted
by hand and audited only for their headings, and most had drifted in prose
no audit could see.

**Keep a census out of this document.** A count written here is copied
into every tree and goes stale in all of them at once; state the rule and
the criterion that decides it, and keep the count where it can be
recounted once.

**This source is plain ASCII**, so that it is valid in a tree whose own
rules restrict the characters its files may contain. Keep it so.

**Re-read this source before writing a project's own part, or anything
about the rules**, rather than working from what was loaded at the start of
the session: text written against a stale source is drift being written.
**A copied part that differs from the source** -- a tree the spread has not
reached, a hand edit -- is put right with `sync.py --commit <tree>`, never
by editing the copy; `sync.py --check` lists any that differ. A project's
`project.md` may state the three rules in brief and point here; it does not
restate the precedence rule.

<!-- End of the copied part. What follows is this project's own. -->

## This project

Code style for this project. Applies to the C of the daemon and the CLI
(`c/`), the client library (`client/`), the bridge, the helpers and the
adapters, and to the C++ of `gui/`. netcfgd was first written in Rust, and
several sections below were written for it; 0317 retired the Rust, and what
those sections now say is about the C. `project.md` §9 states the rules in
brief and points here for the detail; where the two ever disagree,
project.md wins.

Sections 4 and 6 through 8 below are this project's own and are not in the
source. The numbering skips 5 deliberately: that section was *Line length*,
withdrawn as a rule nobody had asked for, and the sections after it kept
their numbers so that the references `project.md` and the decision records
already carry keep resolving.

### Exempt paths

Vendored or generated sources are exempt — they keep whatever their
generator or upstream produces. Nothing is vendored yet; when something is,
say so here.

### 1. Naming: the C spelling, and why abbreviations cost more here

Functions, variables, types and fields are `snake_case`; a type ends in
`_t` where the C does (`ncfg_plan_t`), constants and enum members are
`SCREAMING_SNAKE_CASE`. Nothing in C enforces any of it, so all of it is
review. Beyond the spelling:

- **No abbreviations that are not already vocabulary.** `observed`, not
  `obs`; `interface`, not `iff`. This is stricter than ordinary C taste for
  a specific reason: this project's struct field names *are* its JSON field
  names *are* its `/run` file names *are* the dotted paths in a `Reason`
  (§4). An abbreviation invented inside a struct definition ends up in
  `ncfg explain` output and then in somebody's grep, where it can no longer
  be renamed. Names in `netcfgd-model` are a public interface even before
  the schema freezes at M4.
- **One word per concept, everywhere.** `desired` and `observed` are the
  clearest case: the same word in the type name, the `/run` path, the CLI
  subcommand and the documentation, and no synonym anywhere. A synonym
  introduced for variety is a second concept as far as any reader is
  concerned. `doc/decision/0005-state-vocabulary.md` settles which pair,
  and rules out carrying both as aliases.
- **Prefer the plain descriptive name over the redundant one.** The type a
  planner returns is `Plan`, not `PlanStruct` or `PlanResult`;
  `netcfgd_plan::Plan` already reads correctly at the call site, and
  stuttering only shows up once someone imports it.

**A toolkit whose own API is `camelCase` does not pull your names across.**
Call the foreign API exactly as it is spelled -- `setParent`, `addWidget`,
`setEnabled` -- because that is not a violation, it is the API's name. But
names *you* introduce stay `snake_case` on the same line. Qt is the
`camelCase` toolkit here, so `gui/` is where it has to be held
deliberately: `ncfg_apply_dialog::build_consent` calling
`consent_box->setVisible` is both halves correct, and neither half should
drift toward the other.

### Prefixes, and visibility: netcfgd's prefixes

**C and C++ do not settle the middle case for you**: anything not `static`
reaches the linker. A symbol that is internal by intent but still reaches
it -- cross-file within a library, not `static`, not part of the API -- is
not private for this purpose. Prefix it. The daemon's library is `ncfg_*`
throughout, `client/` exports `ncfg_client_*` and `ncfg_json_*`, and `gui/`
names its own types `ncfg_apply_dialog` and the like.

### 2. Indentation and alignment: the shape the C takes

If two lines are short enough to merge rather than align, merge them.

The daemon's C continues a long signature on an indented line rather than
lining arguments up under the open paren, which keeps alignment out of most
of the tree:

```c
int ncfg_openvpn_command(ncfg_openvpn_management_t *management, const char *command,
→   char *reply, size_t reply_size, char *err, size_t err_size)
{
→   if (!management || !command) {
→   →   return 0;
→   }
```

(`→` marks a tab.) Every leading column there is a tab and nothing is
aligned to a paren, which is the shape to aim for.

In the nine Python scripts under `tests/live/` and `tool/`, mixing tabs and
spaces within the indent is worse than cosmetic: a space *before* a tab in
leading whitespace raises `TabError`, so a file that looks right refuses to
run.

### rustfmt was used here, and went with the Rust

While the daemon was Rust, `rustfmt` was used and gated: it has a stable
`hard_tabs` option, so the rule survived the tool. 0317 retired the Rust,
and `rustfmt.toml` and the `fmt` gate with it. The C has no formatter, for
the reason below.

### No formatter for the C and the C++

`clang-format` is **not run here, not even ad hoc on a single file**, for
the reason the sibling C projects recorded: it rewrites tabs to spaces
unconditionally and cannot be configured out of it. That is a configuration
gap, which is disqualifying rather than something to work around — the
failure mode is a silent conversion of files that were already correct,
found later as a reverted commit rather than as an error.

This is the same evaluation `rustfmt` passed while the Rust was here, and
it fails: the rule has to survive the tool, and here it does not.
`make style` gates indentation and alignment instead.

### 3. Filenames: what this project names

- C and C++ sources are `snake_case`: `wifi_profile.c`, not
  `WifiProfile.c` or `wifi-profile.c`.
- Markdown and other prose files are kebab-cased: `code-style.md`,
  `netcfgd-design.md`.
- Config fixtures and test data follow the thing they describe.

### netcfgd's plural directories, and which kind each is

The source asks the ecosystem-plural exception to be *measured* and named
by the project carrying it, so that the next reader does not reopen it.
Measured 2026-08-26 by listing every tracked path component that ends in
`s`.

**Required by a tool, so not a name this project chooses:**

| directory | what breaks without it |
|---|---|
| `.github/workflows/` | GitHub reads no other path |
| `tool/hooks/` | mirrors `.git/hooks/`, which git names |

**Settled by an ecosystem**: none since 0317. `crates/` and
`fuzz/fuzz_targets/` were the two, the Cargo workspace convention and where
`cargo fuzz add` writes, and both went with the Rust.

**Everything else is singular already**: `adapter/`, `bridge/`, `client/`,
`doc/`, `doc/decision/`, `gui/`, `helper/`, `packaging/`, `tool/`.
`debian/` and `packaging/dbus/` are not plurals, and `debian/rules` is a
file whose name Debian requires.

### 4. ASCII only in source

Source, comments, doc comments, test fixtures and commit messages are
**ASCII**. Write `--` where prose would use an em dash. Three things are
excepted, and they are the rule's shape rather than holes in it:

- **Documentation.** Markdown may use typographic punctuation —
  `project.md` and `netcfgd-design.md` already do throughout, and so does
  this file.
- **User-facing text a program prints.** A glyph in a `gui/` label or a
  tick in `ncfg` output is output, not prose, and the rule has nothing to
  say about it.
- **Anything that genuinely requires Unicode.** `tests/determinism/`
  carries a deliberately non-ASCII SSID, which is the entire point of the
  fixture: a document that survives three architectures unchanged has to
  survive them with its multi-byte characters intact.

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
`tool/`, read with `tokenize`, and the C of `client/` and the C++ of
`gui/`, read with a scanner written for the purpose because nothing in the
standard library lexes them. That is what makes the UI exception above
enforceable rather than merely stated: a glyph inside a `gui/` string
literal passes and an em dash in the comment above it does not.

Markdown is out of the check entirely, which is the documentation
exception.

### 6. Modules and comments

Every source file opens with a comment naming itself and its single
responsibility -- `management.c -- OpenVPN's text control protocol, on a
unix stream socket.` If that comment needs two sentences joined by "and",
the file wants splitting.

This has teeth here rather than being a nicety. `project.md` §5 requires
the model, the compiler and the planner (`c/src/model`, `c/src/compile`,
`c/src/plan`) to be pure and hardware-free, which is what makes the entire
planner unit-testable against fixtures. A file whose stated responsibility
has quietly grown a second half is how I/O first appears in a part that is
supposed to have none.

Comments explain **why**. The what is in the code and stays there; a
comment restating a line is one more thing to keep true. Comment density
should match the surrounding file. The places worth a paragraph are the
ones where the obvious implementation is wrong: ordering edges in the
planner (§4), anything touching `rtm_protocol` and object ownership (§2.3),
and every cast or length at a trust boundary.

### 7. `unsafe`

This section held the Rust's rule -- `#![forbid(unsafe_code)]` in every
crate root, `netcfgd-sys` the one audited exception, a `// SAFETY:` comment
on every block -- and went with the Rust (0317). It keeps its number
because `project.md` and the decision records cite the sections after it.

C has no such boundary to draw, so what stands in for it is where the input
comes from: a length or an offset read off the wire, from netlink, a
supplicant's control socket or a configuration file, is checked against the
buffer before it is used, and the comment beside it says which bound holds
it. The fuzz targets under `c/fuzz/` exist for those parsers.

### 8. Commit messages

Kernel format. See `~/.claude/guidelines/build-and-commit.md` for the full
statement; what is specific here is the subsystem name.

    plan: fix the ordering edge for a renamed link
    nm: rework the containment check as one pass

The subsystem or adapter comes first, followed by a colon, with a slash for
nesting. `git log --grep '^plan:'` then answers what has happened to the
planner without naming paths, and keeps answering after files move. Commits
from the Rust's time name crates (`netcfgd-plan:`), which is why a search
over the whole history wants both spellings.

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

The commit-msg hook is `tool/hooks/commit-msg`, installed with
`make hooks`. It rejects generator attribution, a subject over 75 columns,
and body prose over 75 columns. It lives in the tree rather than only in
`.git/hooks` so that it is reviewable and survives a clone; the copy that
runs is installed from it.

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
over text that never reaches the message -- the hook's own diff contains
its own pattern list, so it rejected every commit that edited it.

**Three shapes the length check exempts**, each because wrapping it is the
actual mistake rather than a concession: a *trailer*, since git parses the
block a line at a time and a broken `Link:` stops being a trailer at all; a
line holding a *url*, which no longer works once it is split; and an
*indented* line, which is how a message quotes a compiler error or a stack
trace, where reflowing what you are quoting corrupts the one thing it was
included for. It cannot tell prose opening `Note:` from a trailer, so it
forgives that -- the wrong way round would refuse a real trailer, and that
is the expensive error.

### See also

- **`project.md` §9** — working in this repo: build and CI conventions, and
  the rules above in brief.
- **`project.md` §1** — the hard constraints. Constraint 4 (`unsafe`) and
  constraint 8 (size budgets as CI gates from commit 1) are the two that
  shape day-to-day code most.
- **`netcfgd-design.md` §12** — why Rust, and the security posture that
  follows from a daemon holding `CAP_NET_ADMIN`.
