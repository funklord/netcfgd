# Transitioning netcfgd to C

Status: exploratory. Nothing is committed to, and this document is written so
that stopping costs one deletion.

The copyright holder has said netcfgd may be rewritten in C, with C++ for the
GUI, and asked that the two implementations live side by side during the
transition so they can be compared for regressions and completeness -- and
that a dead end is an acceptable outcome. This document is separate from
`project.md` for that reason: if the transition is abandoned, this file and the
C tree go together and nothing else in the repository has to be unpicked.

Everything below is measured on this machine unless it says otherwise. Dates
are given because half of it is state that moves.

## 1. Two thirds of the question is already answered

Measured 2026-09-06, tracked files only:

| | lines |
|---|---|
| Rust, total | 96,072 |
| ... of which doc comments | 27,809 (29%) |
| ... of which blank | 5,886 |
| **Rust, actual code** | **62,377** |
| ... of which integration tests | 15,714 |
| **production Rust to rewrite** | **~46,700** |
| already C: `client/`, `gui/` | 16,667 |
| already C++: `gui/` | 17,110 |
| shell and python live tests | 22,907 |

**The GUI question is moot.** `gui/` is Qt Widgets C++ today, with 9,331 lines
of C beside it. It is already the target language and does not move.

**The C client already speaks the protocol.** `client/ncfg_client.c` is 7,336
lines and talks to the daemon over the control socket now.

**The live test suite is language-independent by construction.** 22,907 lines
of shell and python that drive binaries by path and assert on their output and
on the kernel. It does not care what wrote the binary.

So the transition is about the daemon and its sixteen crates, and the harness
that would judge it mostly exists.

## 2. serde is 18% of the binary

The strongest argument for C is size. Decision
[0024](decision/0024-one-binary-and-what-a-megabyte-would-actually-cost.md)
measured 1 MB as unreachable and reached 1.75 MB with a multi-call binary;
today's installed total is 2,771,480 bytes. **The entire external dependency
graph is `libc` and `serde`** -- with `serde_derive`, `serde_json`, `itoa`,
`memchr`, `zmij` and the proc-macro crates that build them. Everything else in
this tree is hand-written. So "how much is serde" is very close to "how much
would a C rewrite not have to carry".

**Measured two ways, agreeing within 5%.**

*Method A, symbol attribution over the real binary.* Built with
`CARGO_PROFILE_RELEASE_STRIP=false` (which moved `.text` by 368 bytes, 0.018%,
so the attribution transfers), then `nm -SC` and summed by demangled name:

    netcfgd's own derived codecs      267,993
    serde and serde_json themselves   232,562
    itoa, memchr, zmij                  7,529
    ------------------------------------------
    serde, total                      508,084   18.3% of 2,771,480

    for scale, same method:
    netcfgd code with no serde in it  823,089
    everything else (std, core, ...)  700,308
    attributed by symbol            2,023,952

*Method B, a link differential.* Four binaries in a scratch crate outside the
tree, same release profile, each adding one thing to the last:

    a Document constructed and read, nothing serialised     330,160
    + serde_json on a trivial type                          358,848   +28,688
    + one Document round trip                               723,392  +364,544
    + one Request round trip                                813,504   +90,112

Method B covers only `Document` and `Request`; the real binary also serialises
`Observed`, the journal and the host's state files. It totals 483,344 against
Method A's 508,084 for everything, so the two are consistent and A is if
anything conservative.

**The decision-relevant split is inside that number.** Method B measures the
JSON library itself at **28,688 bytes** -- the reader, the writer, number
formatting and the error type. Everything else is *generated codecs*: code
somebody would write by hand in C, and hand-written codecs are far smaller than
monomorphised generic ones. The clearest instance is `netcfgd-model`, which
Method A splits as 168,328 bytes of derived codecs against 53,037 bytes of
everything else: **the model crate is three quarters serialization.**

**Caveats, because both methods are proxies.** Method A under-counts serde code
that was inlined into a caller and over-counts a netcfgd function that merely
names serde in a generic parameter; `opt-level = "z"` limits the first. Method
B pays for each monomorphisation separately where the real binary shares some
under LTO, which is why its per-type split is larger than A's while its total
is smaller.

## 3. Do the cheap experiment before the expensive one

**Replace serde with hand-written codecs in Rust first, and re-measure.**

If most of that 508 KB comes back, the size argument for the transition has
been satisfied without one -- keeping exhaustiveness checking, keeping
`forbid(unsafe_code)`, keeping the tests. If it does not, the experiment has
produced a real number to decide on instead of an estimate, and the codecs it
produces are the ones a C port would need anyway, written once in a language
that will tell you when they are wrong.

It is days of work against months. Nothing else in this document should start
before it has been done.

## 4. The tree during the transition

**One rule, and everything else follows from it: nothing in the Rust build may
depend on the C tree.**

- The C implementation lives in one directory. Its own Makefile targets, its
  own build directory under `$(BUILD_DIR)`.
- `make` builds what it builds today. A separate target builds the C daemon.
- Ending the transition is deleting that directory, this document, and the
  Makefile lines that name them. Nothing else changes, and `project.md` never
  learned about it.

That last property is the whole reason for the arrangement. A transition that
entangles itself with the thing it is replacing cannot be abandoned, only
finished -- which turns "we might stop" into a sentence nobody can act on.

## 5. How the two are compared

Four oracles, and three of them already exist.

**The live suite.** 22,907 lines already assert against a real kernel, a real
supplicant and real sockets. Today every script hardcodes
`$repo/target/debug/ncfg` -- 88 sites -- and `$repo/target/debug/netcfgd` -- 66
sites. Taking that directory from an environment variable is the one change the
harness needs, and it is a mechanical edit that carries a proof: every script
must produce a byte-identical run against the Rust binaries before and after.

**The schema witnesses.** `doc/schema/` holds four byte-exact artifacts --
`document.json` (115 KB), `observed.json`, `plan.json` and `socket.json` --
blessed deliberately by `make schema-bless` under decision
[0020](decision/0020-the-freeze-is-two-witnesses.md). **Both implementations
must reproduce them byte for byte.** That is the completeness test for the
model, the observation, the plan and the protocol at once, checked
mechanically, and `plan.json` in particular is a witness of the planner's
output -- the hardest crate, with an oracle already written for it.

**The canonical verbs.** `ncfg show --json`, `ncfg plan --json` and
`ncfg status --json` each print an artifact that is a pure function of the
config and the kernel. Same config in, same bytes out, or the C side is wrong.

**A completeness ledger, and it must be derived rather than kept by hand.** The
question "what does the C side not do yet" is answered by asking the C daemon
-- a `--supported` dump, or an extended `Hello` -- and diffing that against the
Rust side's own request and action taxonomy. A hand-written checklist of
supported features is exactly the shape this workspace has been burned by
repeatedly: a list that quietly stops matching the thing it describes, under a
name that claims it is exhaustive.

## 6. What is lost, and it is already written down

`project.md` section 1 records it: constraint 4 is the only one of the nine
written in a language rather than a property. One audited directory and a gate
naming it *is* expressible in C -- that is what the constraint is really
bounding. The **guarantee** is not: `forbid(unsafe_code)` is a compiler refusal,
and a directory convention is checked by whoever is looking. State the property
when restating it; do not claim the guarantee.

The second loss is not in that note and is worth adding here, because it is
about how this project actually finds defects. **Exhaustiveness checking is a
working guard, not a nicety.** In the first week of September it caught, on its
own: every construction site of `RemotePolicy` when that type gained a field
(0159), and both call sites of `server::serve` when its signature changed. The
planner is 16,405 lines of exhaustive matching over 42 model enums with about
54 payload-carrying variants. In C those become tagged unions and the checking
goes away.

Of 160 decision records, 35 mention Rust at all. The design, the DSL, the
protocol, the witnesses, the live tests and the packaging all survive a
rewrite untouched.

## 7. The order to port, and what each stage is worth

By symbol attribution (bytes) and source size (lines of code):

Bytes are Method A's symbol attribution; code lines exclude comments and blanks,
which is a third of this tree.

| crate | bytes | code | difficulty |
|---|---|---|---|
| `netcfgd-sys` | 22,811 | 5,442 | **transliteration.** rtnetlink codec, 60 `unsafe` sites, the one crate already permitted them. This is C written in Rust. |
| `netcfgd-ra`, `-openvpn`, `-hostapd`, `-dns`, `-secret`, `-supplicant` | 35,809 | 5,422 | **straightforward.** Writing files, spawning processes, text protocols. |
| `netcfgd-model`, `-proto` | 291,255 | 6,439 | **the serde question.** The largest byte count in the tree against one of the smallest source counts, which is the whole finding: it is generated code. Section 3 decides whether it is written once or twice. |
| `netcfgd-observe`, `-apply` | 163,802 | 4,831 | **moderate.** Kernel dumps to model, model to syscalls. |
| `netcfgd-compile` | 133,369 | 8,692 | **moderate.** A hand-written lexer and lowering pass with spans. No dependency to replace. |
| `netcfgd-plan` | 104,775 | 11,606 | **the hard one.** Pure, thoroughly tested, and almost entirely exhaustive matching over sum types. `plan.json` is its oracle. |
| `netcfgd-daemon`, `-host`, `-cli` | 342,427 | 14,198 | **moderate**, and last, because they are what the others are for. |

The two columns disagree about where the work is, and that disagreement is the
most useful thing in the table. `netcfgd-model` and `netcfgd-proto` are 6,439
lines of source and 291,255 bytes of binary; `netcfgd-plan` is 11,606 lines and
104,775 bytes. **Size is concentrated in what a machine generated; effort is
concentrated in what a person wrote.** A C port pays the second in full and
recovers most of the first.

Port in that order and the differential harness has something to compare at
every stage: `netcfgd-sys` against the same netlink dumps, the backends against
the same `/run` artifacts, the model against `document.json`, the planner
against `plan.json`.

## 8. What would end this

Named in advance, so that stopping is a measurement rather than a mood.

- **The Rust-side codec replacement in section 3 recovers most of the 508 KB.**
  Then the size argument is spent and there is no other one on the table.
- **The differential cannot be made to agree on the witnesses**, and the
  disagreement is in the model or the planner rather than in a backend. Those
  two are where byte-exactness is the contract.
- **The completeness ledger stops shrinking.** A transition that stalls at 80%
  is worse than either end state, because every fix then has to be made twice.
- **A defect class appears in the C side that the Rust side structurally could
  not have.** One is a data point; a pattern is the answer to the question this
  document is asking.

If any of those happens, the arrangement in section 4 means the ending is a
`git rm -r` and a note here saying which one it was.
