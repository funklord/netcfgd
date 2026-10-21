# 0277: a fuzz target is replayed as well as fuzzed

Status: accepted
Date: 2026-10-21
Milestone: M9; the C port

## What this decides

`make fuzz` fuzzes the C parsers. There is one target per parser under
`c/fuzz/`, each a plain `ncfg_fuzz_one()` over a byte string, and **two drivers
over the same function**:

    fuzz/<target>_replay   the ordinary compiler, over the committed corpus.
                           Deterministic, needs no clang, and runs inside
                           `make -C c test` -- so inside `make check`.
    fuzz/<target>_fuzz     clang's libFuzzer, coverage-guided. `make fuzz`
                           drives these; nothing else does.

`make fuzz-rust` is the old cargo-fuzz path, kept because the Rust is still the
instrument `make agree` compares against.

Decided by the copyright holder on 2026-10-21: "now fix the fuzz gate too",
after `linkage` and the budget gates.

## Why two drivers and not one

Design section 12 asks for "all parsers continuously fuzzed as part of CI, not
as an occasional exercise". The tree had that through cargo-fuzz and **lost it
the day the C became what ships**: five Rust targets went on fuzzing five Rust
parsers that no longer run, and 0276 recorded the gap rather than closing it.

Pointing a fuzzer at the C would have answered the first clause and not the
second. **A fuzzer explores and does not remember.** Run it again, on another
machine or with another seed, and it goes somewhere else -- so "that crash is
fixed" is a claim nothing re-checks, and a crash found on a laptop in October
is rediscovered by somebody else in March or not at all.

So the corpus is the memory, and replaying it is the gate:

* a crash becomes a file in `c/fuzz/corpus/<target>/`, committed;
* `make -C c test` runs every committed input through the same
  `ncfg_fuzz_one()` with the ordinary compiler;
* that needs no clang and no nightly, which is what makes it run on the
  machine a regression arrives on rather than on the one that found the bug.

The split also keeps a non-deterministic thing out of a gate. A fuzz run's
verdict depends on where its seed took it, and a gate that fails on a tree
nobody changed is a gate people learn to re-run rather than read.

## The five targets, and why those five

The Rust's own set, parser for parser, because the argument for each was made
when it was written and has not changed:

    config_parse     the DSL, through to a canonicalised document. `conf.d/`
                     is writable by anything that can write to /etc
    document_json    the desired-state document, which /run holds and clients
                     read. The round trip is the assertion, not the parse
    netlink_wire     the kernel's messages, and the one that matters most: a
                     privileged reader of bytes whose lengths it must not trust
    backend_ipc      what wpa_supplicant and hostapd reply. A LOWER-trust
                     boundary than the kernel, from a process netcfgd starts
                     but does not contain
    socket_message   the control protocol's framing and its messages, which a
                     member of group `netcfgd` can send

**`netlink_wire` asserts termination as well as safety**, which no sanitizer
can do for it: a length field that makes no progress is an infinite loop that
looks from outside like a slow input. Every walk is bounded by a count and the
bound aborts, which is what the Rust target's `take(10_000)` is for.

## What was proved before this was committed

**A fuzzer that finds nothing looks exactly like a broken one.** Five controls,
because the thing being built here is a detector:

* **It finds coverage.** 50,000 runs per target added 1,145 new units for
  `config_parse`, 1,104 for `backend_ipc`, 688 for `document_json` and 255 for
  `netlink_wire`. A target that returned early would add none.
* **It finds a real defect.** In a scratch copy with one bounds check removed
  from `ncfg_wire_attrs_next` -- the `len > remaining` refusal -- the fuzzer
  reported a heap-buffer-overflow in `ncfg_wire_attr_string` after about 220
  executions, named the line, and wrote a nine-byte reproducer.
* **The reproducer is now a regression input.** It is
  `corpus/netlink_wire/attr-longer-than-the-area.bin`, it replays clean against
  the real code, and it will keep replaying -- which is the whole loop this
  record is about, demonstrated rather than described.
* **The corpus is clean under the sanitizers**, not only at `-Os`:
  `make -C c SANITIZE=1 fuzz-replay` passes, which is ASan and UBSan over every
  committed input.
* **An empty corpus fails.** A directory with no inputs is refused by name
  rather than skipped, and the replay binary refuses zero arguments with its
  own sentence. A replay over no files is a pass that inspected nothing, which
  is the failure this tree keeps finding.

## What this does not claim

**`make fuzz` is not in `make check` and the exploring half is not continuous
here.** Nothing in this tree runs a fuzzer on a schedule; CI is declined
outright for cost (see `build-and-commit.md`), so "continuous" means a person
typing `make fuzz`, and the honest version of section 12's sentence is that the
*corpus* is continuous and the *fuzzing* is not. The design document says so in
those words rather than claiming the stronger thing.

**The sanitizers are not gated either.** `make SANITIZE=1` builds them and no
target runs them by default, which was true before this record and still is.
What changed is that there is now something worth pointing them at: the corpus.

**Five parsers is not every parser.** The NetworkManager shim's dictionary
reader takes `a{sa{sv}}` from any client on the system bus and is not fuzzed
here -- it lives in the adapter, it needs libdbus to build, and that is its own
piece of work rather than a line in this one.
