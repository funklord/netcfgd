# 0235: a reason that was not one

Status: accepted
Date: 2026-09-14
Milestone: M9; the thread lifetime audit

## The question

Asked, after 0233 and 0234 had both fixed faults that exist only because the
daemon's watchers are threads: *why are these threads, rather than one epoll
loop?*

The daemon's own header answered it:

> No locks, because nothing is shared; no async runtime, because a daemon whose
> steady state is "asleep on a channel" does not need one; **no epoll, because
> that would mean `unsafe` outside the one crate allowed it.**

The first two clauses are true. The third is not, and the tree contradicts it
one call away.

## What the tree already does

`netcfgd_sys::signals::wait` is a two-descriptor `libc::poll`, with the `unsafe`
inside `netcfgd-sys` behind a safe signature -- which is precisely what
constraint 4 asks for. `Watcher::wait` is a `poll` as well: the config thread
shows up in `do_sys_poll` in a thread dump of the running daemon.

So the daemon already depends on polling, through safe wrappers, on the very
threads the comment was justifying. An `epoll` or a wider `poll` would live in
the same crate as those. **Constraint 4 is about where `unsafe` lives, not about
which I/O shape is allowed**, and multiplexing does not touch it.

`server.rs` carried the same non-sequitur -- "that keeps every crate but
`netcfgd-sys` free of `unsafe` (constraint 4)" -- attached to a choice that has
a genuine reason of its own, which it also states. The genuine reason stays and
the non-sequitur is gone.

## Why this is worth a decision rather than an edit

A comment that records a technical impossibility stops the next reader from
considering the alternative. Nobody re-examines a door marked "cannot be
opened". That is the whole cost here, and it is not small: the shape being
defended is the one that produced the faults in 0233 and 0234.

What the threads actually cost, now that it has been measured twice:

- **0233**: a watcher thread returned on an `EINTR` and took the reconcile
  loop's heartbeat with it, because the heartbeat was something that thread
  sent. Fifty-two minutes of a daemon that was `active` and doing nothing.
- **0234**: five spawns discarded their `Result`, so a thread that never
  started was indistinguishable from one that was running -- including the
  timer that closes a commit-confirm window.

Neither is reachable in a single loop. There is no thread to return, and no
spawn to fail.

Against that, `EINTR` is *not* fixed by changing shape -- a poll loop is
interrupted too. But there would be one place to get it right rather than four,
and the evidence that the number matters is in this tree: `signals::wait`,
`inotify` and `lock` all handle it correctly and `Netlink::wait_for_change` did
not, which is the one that broke.

## What is not being changed, and why

The watchers could be one loop. Every source is a pollable descriptor -- the
netlink socket, the inotify descriptor, `/dev/rfkill`, the supplicant control
sockets, the listener -- and the tick is the poll timeout.

The **workers** are a different question with a different answer. A client
connection blocks on a reader that may stop reading, and a scan takes seconds;
those are threads for a reason that survives any shape the watchers take, and
`serve` already handles their failure correctly.

Restructuring the core of a working daemon is its own piece of work with its own
risk, and the faults are fixed and tested. So: the comment is corrected to say
what is true -- that this is a preference, what it costs, and that collapsing the
watchers is available whenever it is wanted -- and the restructure is a design
question left open rather than begun as a footnote to a bug fix.

## What this says about comments

This tree's comments are unusually load-bearing: they carry the reasoning, and
the audits in this campaign have repeatedly used them as evidence. Twice now
that has cut the other way -- 0230 found a test whose doc comment stated the
hazard in the same paragraph as the assertion that embodied it, and this is a
header that stated a constraint the code beside it does not have.

A comment that gives a reason is a claim, and claims are checkable. This one was
never checked because it sounded like a rule.
