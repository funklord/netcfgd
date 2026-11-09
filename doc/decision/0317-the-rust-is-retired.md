# 0317: the Rust is retired

Status: accepted
Date: 2026-11-09
Milestone: the C port
Supersedes: [0266](0266-the-c-port-is-what-ships.md)'s "the Rust stays in the tree and is not deleted"

## The holder's words

"let's also retire anything in rust that blocks work, or causes extra work."

## What this decides

**netcfgd has one implementation and it is the C.** The Rust workspace --
`crates/`, `backend/`, the cargo-fuzz targets under `fuzz/`, `Cargo.toml`,
`Cargo.lock`, `rustfmt.toml` and `deny.toml`, about 106,000 lines -- is
deleted, and so is every gate that built it, ran it, or read its source.

0266 shipped the C and kept the Rust as the instrument that had proved it:
"deleting the Rust the moment parity was reached would have retired the only
thing a future C regression could be measured against." That was the right
call then, when the C had not run a machine. Since then it has run them --
`hull-malta` and `hull-mips` on two byte orders, `vm-sandbox` under systemd
257, `vm-cluster`, `vm-skipped` seven of seven, 90 live scripts on this
machine -- and nothing ships the Rust. What the comparison still cost was the
work: every `make check` built the Rust workspace twice (debug for `test`,
release for `agree`), every change to a message the two programs shared had
to be made twice or declared as a difference, and the C kept code paths
whose only remaining caller was a comparison script.

## Every Rust gate checked only the Rust

That is what made this a deletion rather than a migration, and it was
measured before anything was removed: no gate removed here asserted
anything about the C.

    fmt, clippy             rustfmt and clippy over the workspace
    unsafe-policy           forbid(unsafe_code) in every crate root
    executor-policy         a Rust executor built without the document
    test                    cargo test --workspace
    conformance             the Rust CLI against client/, one fact list
    agree                   the C against the Rust, show and the verbs
    deny, cross, fuzz-rust  cargo-deny, a Rust cross build, cargo-fuzz
    nm-containment          the core's Cargo.lock against deny.toml
    op, privilege,          python gates that parse crates/ and backend/:
    supplicant_coverage,    planned ops against executor arms, config keys
    print, disarm,          against privilege classes, supplicant settings,
    doc_comment, write,     println!, test disarming, doc comments, dropped
    tag_producer, sandbox   write Results, a tag's producers, /etc writes

`nm-containment`'s two halves are both `linkage`'s now: constraint 3 is
`linkage-one` over `c/netcfgd`, and the shim's D-Bus coming from the system is
`LINKAGE_REQUIRED_NM`.

**Five of those gates enforced a property the C should hold too and has no
gate for**: `sandbox` (every `/etc` path written is one the unit grants),
`op` (every op the planner can emit has an executor arm), `supplicant_coverage`,
`privilege` (every key classified) and `write` (no write failure dropped
silently). Deleting the Rust versions takes nothing from the C, which they
never read; porting them is open work, recorded in project.md 10.759.

## What the comparison scripts became

The live scripts that used the Rust as their oracle keep their checks
against the C alone:

- `c_link_settings.sh` asserts each device's settings against the values the
  document asked for, read back by `ip -d` -- the bridge half already did;
  bond, vxlan, vlan and macvlan now do too.
- `c_warnings.sh` and `c_dns_delivery.sh` hold the C to the exact lines it
  produced on the day the comparison last passed: each line is one two
  implementations written apart agreed on, or a declared difference.
- `c_wireguard.sh` reads the kernel through `wg` instead of the Rust `ncfg`,
  and asks more of it: the whole private key the device holds, clamped.
- `c_daemon_answers.sh` keeps what needs one daemon: every verb answered, a
  reload that only a daemon can answer, the daemon still running, and the
  files the writing verbs must leave.
- `make live` runs `c/tests/shed_test` under `unshare -rn`, the only place the
  C's privilege drop is observable -- which is the reason the Rust's
  `netcfgd-sys` tests were run there.

`tool/agree_gate.py` and its corpus `tests/agree/` are deleted rather than
frozen. Freezing would pin 27 invocations' help and usage text, which moves
whenever the text does -- the extra work this decision is removing -- and the
C's own CLI unit tests and the `example`, `ledger` and `registry` gates hold
what it compared.

## What is not decided here

**The no-node daemon's `netcfgd.sock`.** 0309 left it to a daemon with no
node, and project.md 10.738 records that what such a daemon should do -- stop,
or keep the socket -- is the holder's. The Rust's comparisons were one of its
callers and are gone; the live scripts and the unit tests still wait on it,
and the decision is unchanged by this one.

**History stays readable.** Decision records quoting `crates/` and `backend/`
are not edited; `cited_quote_gate.py` counts a quotation from a tree that no
longer exists as history rather than as a wrong claim, which is
`style_gate.py docs`' rule for a backticked path under a removed directory.
`git show dcbc20ee:crates/...` reads any of it.
