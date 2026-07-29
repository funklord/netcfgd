# 0012: the audited crate is defined by its privilege, not its protocol

Status: accepted
Date: 2026-07-29
Milestone: M2

## Context

Section 1 constraint 4: `#![forbid(unsafe_code)]` everywhere except
`netcfgd-netlink`, "which is the sole audited exception and carries its own
fuzz targets and review bar".

M2's daemon has to notice that the config directory changed. Section 7 says
inotify. inotify is a raw syscall, and `netcfgd-netlink` is named for a
different one.

Three ways to hold that:

1. Put inotify in `netcfgd-netlink` and accept that the name describes the
   larger half rather than the whole.
2. Add a second crate -- `netcfgd-sys`, say -- with its own `unsafe`.
3. Avoid inotify entirely and poll mtimes, which needs no `unsafe` at all.

## Decision

**inotify goes in `netcfgd-netlink`, and the fallback is kept.**

The constraint counts crates because what it is really bounding is *audit
surface*. A second crate with `unsafe` would be a second thing to review to
the same bar, a second place a fuzz target has to exist, and a second entry in
the Makefile's `unsafe-policy` gate -- which currently reads "everything
except this one name" and would become a list. Lists grow. The constraint says
"sole", and the cheapest way to keep that true is to put the syscall where the
syscalls already are.

The name becomes imprecise, and that is the cost. It is worth less than the
audit property: a reviewer asking "where is the `unsafe`?" gets one answer
either way, and the crate's own documentation now says it is named for the
larger half. Renaming to `netcfgd-sys` was considered and rejected -- the name
appears in constraint 4, in section 5's layout, in the Makefile gate, and in
the crates.io reservation section 0 asks for, so changing it costs more edits
than the imprecision costs readers.

**The fallback is not optional.** `inotify_init1` fails with `EMFILE` when
`fs.inotify.max_user_instances` is exhausted, which happens on real machines
running enough watchers, and some container runtimes and hardened kernels
restrict it outright. A config daemon that stops noticing config changes
because a limit somewhere else was reached is worse than one that polls, so
`Watcher` tries inotify and falls back to comparing mtimes.

`Watcher::polling` is public rather than test-only, for two reasons: an
operator debugging a reload that is not happening wants to take inotify out of
the picture, and a fallback that only runs when something else has already
gone wrong is a fallback nobody has ever watched work.

## Consequences

**The same discipline applies to the new syscalls as to the old ones.** The
`unsafe` is four calls -- `inotify_init1`, `inotify_add_watch`, `poll`, `read`
-- each with a SAFETY comment, and the parsing of what comes back is entirely
safe code with the same two obligations as the netlink iterators: terminate,
and do not panic. A `len` field running past the buffer ends iteration.

**Kernel-dropped events are a change, not an error.** `IN_Q_OVERFLOW` is
handled exactly as netlink's `ENOBUFS` is, and for the same reason: a watcher
that re-reads everything cannot tell a lost event from an ordinary one, and
refusing to look would stop the watch precisely when the most was happening.

**Both mechanisms are held to the same assertions.** Writing this record's
tests found a real hole: a directory's own mtime changes when a file is
created or deleted inside it, so the create and delete tests passed even with
child fingerprinting removed entirely. Editing an existing file does *not*
change the directory's mtime, and that is the common case -- an operator
editing `netcfgd.conf`. The gap stayed open until the fingerprint was
deliberately broken and nothing failed. There is now a test for modification,
and it fails without the child fingerprint.

## Alternatives considered

**A second `unsafe` crate.** Rejected: it doubles the audit surface the
constraint exists to bound, and "sole exception" stops being checkable by
reading one name.

**Polling only, no inotify.** Rejected. Section 7 asks for inotify, and the
latency difference is real on a machine where a config change should take
effect promptly. Polling as the only mechanism also means choosing an interval
that is either wasteful or slow, with no good answer.

**inotify only, no fallback.** Rejected on the `EMFILE` case, which is
ordinary rather than exotic. The failure mode -- a daemon that silently stops
reloading -- is one an operator would not diagnose quickly, because everything
else about it keeps working.
