# 0266: the C port is what ships

Status: accepted
Date: 2026-09-26
Milestone: M9; the C port

## What this decides

`make build` builds the C. `make install` installs the C. Every package built
from this tree ships the C daemon and the C client.

**The Rust stays in the tree and is not deleted.** It is no longer built by the
default target and no longer installed by anything.

Decided by the copyright holder. 0265 made the C daemon reconcile by default
and said in as many words that it "does not settle which implementation ships";
this is that.

## Why the Rust stays

Because it is the instrument that proved the C correct, and the proof is a
*comparison*.

    tool/agree_gate.py        11 configurations, 27 read-only invocations,
                              10 sequences of writing verbs, 5 of the daemon's
                              own -- all of them "do the two programs agree"
    c_daemon_answers.sh       both daemons, side by side, same questions
    tests/live/*.sh           79 scripts whose verdict for the C is only
                              meaningful against the same run for the Rust

Deleting the Rust the moment parity was reached would have retired the only
thing a future C regression could be measured against. That is the same
argument 0265 made about evidence, pointed at the tooling instead of the
daemon: the C has been shown to agree with a known-good implementation, and it
has still not run a machine for a month.

So the retirement is of the *shipped artifact*, not of the source. What that
costs is a tree that stays large and a `make check` that still needs a Rust
toolchain. What it buys is that `make agree` still answers.

The gates keep working because each builds what it needs. `agree` gained two
lines for exactly this reason -- it used to rely on `build` having produced
`target/debug/ncfg`, and `build` does not produce it any more, so the gate now
builds the release binary and its symlink itself. Verified by deleting both
symlinks and watching the gate rebuild and pass rather than go red.

## What is not retired, and cannot be

**`adapter/netcfgd-nm` is Rust and stays Rust.** It is its own cargo workspace,
`make nm` builds it, `make install-nm` installs it, and it ships as
`netcfgd-nm.service` -- the shim that lets NetworkManager's own clients reach
netcfgd. 0264 decided its C replacement is `libdbus-1` and "not yet".

So `cargo` and `rustc` remain build dependencies of the Debian package, and
`debian/control` now says why in a comment: removing them would produce a
package with no NetworkManager shim in it. That is the one line somebody
tidying up would delete without noticing.

**The Qt client is C++** and was never affected.

## The sizes, measured

Both daemons are multicall binaries -- `ncfg` is a symlink to `netcfgd` -- so
this is one binary against one binary.

    rust netcfgd   release, opt-level="z", lto, stripped   2,972,192   2.83 MiB
    c netcfgd      -Os, stripped                           1,023,360   0.98 MiB
    c netcfgd      -Os, as built                           1,145,336   1.09 MiB

**The C is 2.9 times smaller: about 1.86 MiB off the installed daemon.**

Source goes the other way, which is what C costs:

    rust core (crates + backend, tests inline)   103,906 lines   65,123 non-comment
    c, without tests                             140,355 lines   81,160 non-comment
    c tests (separate files)                      92,581 lines   64,649 non-comment

About 2.2 times the source for the same behaviour, and roughly 42% of the C's
non-test lines are comment.

## What this leaves wrong, named rather than fixed

**The budget gates measure a binary nobody ships.** `size` checks
`target/release/netcfgd` against `size-budget.txt`, `rss` runs the release Rust
daemon and measures its resident set, and `footprint` runs the debug Rust
daemon and reads what it left in `/run`. All three still pass, and all three are
now about the wrong artifact.

Not re-pointed here on purpose. `size-budget.txt` is a calibrated file and the
C's numbers are not the Rust's -- the binary is a third the size, so the gate
would pass for a reason that has nothing to do with the budget holding. Moving a
budget in the same change that moves what it measures is how a ratchet stops
ratcheting. It is a pass of its own, with its own re-calibration, and the
`footprint` half is the easy one: the two programs now write byte-identical
files under `/run`, which 10.287 measured.

**`make live` and `make cross` still drive the Rust.** `live` builds the
workspace and runs Rust-only unit tests that have no C equivalent (`wg-*`,
`netcfgd-sys`); `cross` cross-compiles the Rust. Neither is a shipping
question and neither was touched.

**Whether `fmake` can build the C daemon is untested.** It could not build the
Rust one because the daemon was a cargo workspace and fmake drives `rustc` one
crate root at a time. That reason is gone. The README says it is untested
rather than claiming either answer, because `harmonization.md` requires an
fmake line in a README to have been run before it is written.
