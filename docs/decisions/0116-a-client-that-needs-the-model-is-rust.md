# 0116: A client that needs the model is Rust, one that only speaks the socket may be either

Status: accepted
Date: 2026-08-06
Milestone: direction for the three clients; settles the fuzzypickles question

## Context

`fuzzypickles` has the same four directories netcfgd has -- `cli/`, `tui/`,
`gui/`, `client/` -- and one rule holding them together, stated in its
`tui/Makefile`:

> Deliberately thin: everything non-visual lives in client/, shared with the
> Qt frontend.

All three of its applications sit on one C `client/`. netcfgd does not follow
that rule: `ncfg` and `ncfg tui` are Rust inside `crates/netcfgd-cli`, and only
the GUI uses the C `client/`. That is two implementations of one socket
protocol, which is the shape that produced [0082](0082-one-operation-has-one-name.md)
and [0083](0083-the-tag-is-the-name.md) when a plan and a journal disagreed
about what an operation was called.

The question is whether to harmonise the language as well as the layout.

## What each client actually needs, measured rather than assumed

**`ncfg` cannot be a socket client.** `command_plan` calls `build_plan`, which
compiles the config and computes the plan **locally, with no daemon involved**,
and then writes the desired and observed state it used. That is not incidental:
constraint 7 requires `ncfg plan` to survive to the smallest build, because "a
black box on an embedded device with no console is worse than one on a laptop".
So `ncfg` links the compiler, the planner and the observer -- it is the core
with a command-line front, not a client of it.

**`ncfg tui` is a pure socket client.** Its imports are `netcfgd_proto`,
`netcfgd_host::state` and `netcfgd_sys` for curses, signals and the terminal.
It does not touch `netcfgd-model`, `netcfgd-compile` or `netcfgd-plan`.
Everything it draws arrives as a `Request` over the socket: `Hello`, `Status`,
`Plan`, `Apply`, `Confirm`, `Revert`, `WifiScan`, `WifiConnect`, `ApStations`.

**`gui` is already C++ over the C client**, and Qt Widgets is settled elsewhere.

So the three do not share one nature, and a single language rule would have to
be wrong about one of them.

## Decision

**Harmonise the shape, not the language.** The dividing line is the model:

- A client that needs the model, the compiler or the planner is **Rust**, and
  `ncfg` is the only one. Rewriting it in C means reimplementing the compiler
  and the planner, which is a second core -- refused for the reasons
  [0115](0115-the-way-back-in-is-not-ours-to-configure.md) gives about two
  implementations of a thing whose agreement cannot be pinned by a witness, and
  because constraint 1 makes two cores that disagree worse than one core with a
  bug.
- A client that only speaks the socket may be **either**, and a *new* one should
  prefer C over `client/` so that it shares an implementation with the GUI
  rather than adding a third.

"The shape" is concrete, and it is the part worth copying from the sibling:
one vocabulary across all three clients, the same names for the same panes and
tabs, and **nothing non-visual in a view** -- if a client computes something,
that computation belongs where every client can reach it.

## What this does not do, and why

**It does not move `ncfg tui` to C.** The TUI is the one client that *could*
move, and there is no reason to beyond symmetry. It works, it shares
`netcfgd-proto`'s types with the daemon so it cannot drift from them by
construction, and rewriting a working component of a system that has not yet
proven itself is the specific risk this project has just written into its
status: a rewrite is a translation problem when the semantics are settled and
the tests are accurate, and a design problem when they are not. Doing it now
would be paying that cost to make two trees look alike.

That is a deferral, not a refusal. It becomes worth revisiting if something
real asks for it -- a build with no Rust toolchain, or wanting the TUI and the
GUI to share pane logic rather than merely agree about it.

## The prerequisite, which is missing

Two implementations are only two witnesses if there is a specification to be
independent *against*. There is not: `docs/schema/socket.json` is 3 KB of
example messages, there is no prose protocol document in `docs/`, and nothing
runs both clients against one server and compares. Today the second
implementation is not a check on the first, it is a guess about it -- and 0082
found its defect by accident rather than by any gate.

**So the protocol specification and a conformance test running both clients
come before any third implementation**, and before the harmonisation above is
worth much. That work is also what the sibling's clients would be written
against if the two projects ever do share anything.

The constraint-6 analogue applies to it: no change to the socket may be
justified solely by one client's needs.

## Rejected

**Rewriting `ncfg` in C to match the sibling.** It trades constraint 7 and the
type-sharing between the CLI and the daemon for symmetry with another project,
and it lands a second implementation of the compiler and planner.

**Extracting a shared client library across the two projects now.**
`harmonization.md` is explicit that this is its own deliberate piece of work
with the whole picture in view, and neither project's protocol is specified yet.
The observation is worth having; acting on it in passing is not.
