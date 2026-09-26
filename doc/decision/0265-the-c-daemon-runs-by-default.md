# 0265: the C daemon runs by default

Status: accepted
Date: 2026-09-26
Milestone: M9; the C port

## What this decides

`netcfgd` built from `c/` starts its reconcile loop when it is started, with no
flag. `--try-the-c-daemon` is retired: still accepted, no longer documented, no
longer load-bearing.

Decided by the copyright holder. This record exists because the gate it removes
is cited from `project.md` and from 0263, and because a reader who finds those
citations needs to be sent somewhere.

**It supersedes 0263's status note on the gate**, which says "`netcfgd` still
will not start" and gives the reasons then outstanding. 0263 is not edited; the
sentence was true when written and the facts underneath it have since closed.

## What the gate was for, and why removing it is not a reversal of that

The refusal did not name missing code, and had not for some time. Its own
sentence:

> What is missing is evidence -- no netcfgd written in C has run a machine for
> any length of time -- and a loop is the one part of this program that acts
> with nobody at the keyboard.

That is a claim about how much is known, not about what is built, and it is not
a claim a commit can close. It is closed by a decision or not at all.

What has accumulated in the meantime is the nearest thing to evidence this
tree can produce without running the daemon on somebody's machine: the live
suite runs 79 scripts against both programs, 1269 checks each, and **no check
fails for the C port and passes for the Rust** (`project.md` 10.291, 10.292).
The executor refuses nothing that is a port gap; every configuration block the
planner holds is one the Rust holds too; the two programs now agree byte for
byte on the canonical encoding and therefore on a configuration's identity
(10.287).

That is not the same as having run a machine for a month. It is what is
available, and the decision is the holder's.

## What replaces it

**Nothing, and that is deliberate.** A cautious start is spelled
`--no-apply-on-start`, which is what the Rust spells it with: the daemon
observes, watches and changes nothing until asked. There is no C-only opt-out,
because a C-only spelling for "behave like the Rust" is the divergence this
port exists to remove.

`tests/live/c_daemon_tryout.sh` keeps its job. It was written as the "somebody
watching" the refusal asked for, and removing the refusal did not remove the
need for it -- it is still the only arrangement here that lets a real machine
carry a C daemon for a while with something ready to hand the network back.

## The flag

Accepted, undocumented, and it says once that it did nothing.

Accepted rather than refused because a flag that was the documented way to run
this daemon must not become a hard error in the same change that makes it
unnecessary: a unit file carrying it would stop the daemon starting at all,
which is a worse outcome than a line that does nothing.

It says so because of this project's own house rule, the one `log_shape.sh`
applies to an unrecognised `NCFG_LOG`: **a setting nobody can act on must not
be silently ignored.** The sentence goes through the log at note level, so it
is visible at the default and quiet when the operator has turned the log down.

Removed from `--help` rather than documented as vestigial, and that has a
second effect worth naming: the live suite probes `--help` for the flag and
passes it only when it is there. So 34 scripts stopped passing it the moment
this landed, which makes the suite a test of the new default rather than of the
flag.

## What this does not decide

**It does not install anything.** The C daemon is not installed over
`/usr/sbin/netcfgd` by this record, and nothing here starts it on a machine the
Rust daemon is running.

**It does not settle which implementation ships.** Retiring the Rust is a
separate decision with packaging, `VERSION` and the adapter behind it.

## The hazard this exposes, which is not new

A netcfgd of either implementation removes an existing socket before binding
its own -- `server.c` for the C, `server.rs` for the Rust, both deliberately,
so that a stale socket from an unclean shutdown cannot stop a start. Neither
detects a *live* daemon. So a second netcfgd started over a first makes the
first unreachable: it is still running, still holding the network, and every
`ncfg` command now reaches the second one.

That is the reference implementation's behaviour and this record does not
change it. What it changes is that the C daemon will now do it without a flag,
which removes the thing that was incidentally standing between typing `netcfgd`
on a workstation and taking the network off the daemon running it.

**Recorded rather than fixed here**, because a guard the Rust does not have is
a divergence, and this is not the record that decides to add one. Whoever picks
it up: the question is whether a bind should refuse when something answers on
the socket it is about to unlink, and the answer has to be the same in both
programs.
