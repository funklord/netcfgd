# 0122: ownership is changed under a lock, because two processes change it

Status: accepted
Date: 2026-08-08
Milestone: closing the mechanism the brief named first

## Context

The brief has carried this as the mechanism to check first for the
intermittent `qdisc.sh` failure, and called it a real finding either way:

> **`state::write_owned` has no locking, and two processes call it.** `ncfg
> apply` writes it from `netcfgd-cli`, and the daemon writes it from five
> places. It is a read-modify-write of one file, so a lost update is
> structurally possible.

It is, and this closes it. 0121 fixed a second defect found on the same path
-- the staged write sharing one temporary name -- which is about the write.
This is about the read-modify-write around it.

## Why a lost update here is the unsafe direction

The usual reading of a lost update is "one change does not stick". This one is
worse, and the reason is [`OwnedState::absorb`]: it folds in only what *this*
apply did. A pass whose own effects are empty therefore changes nothing and
still writes back everything it read.

So:

```
  daemon: read_owned()            -> { qdisc: ["veth0"] }
  cli:    read_owned()            -> { qdisc: ["veth0"] }
  cli:    absorb(reset veth0)     -> { qdisc: [] }
  cli:    write_owned()                                    <- correct
  daemon: absorb(nothing)         -> { qdisc: ["veth0"] }  <- its stale read
  daemon: write_owned()                                    <- restores it
```

A stale read does not fail to record something. It **puts back** a record the
other process had just dropped, and netcfgd then believes it owns an object it
has given up. Ownership is the thing that decides whether netcfgd may reset a
qdisc, withdraw an address, stop a backend or delete a link at all -- the whole
of `Ownership::may_remove` and the rule that only a link netcfgd created is ever
thrown away. A record that comes back from the dead is a licence to act on
somebody else's device.

Two processes is not an edge case. `ncfg apply` builds a plan and drives an
executor in its own process; the daemon converges on inotify, on netlink events
and on a socket request. Editing a config file while a daemon is running is the
documented way to use this software, and it starts both.

## What was done

One function, `state::update_owned(run_dir, change)`, holding an exclusive lock
across the read, the change and the write. The six hand-written
read-modify-writes call it instead -- five folding in an executor's effects, one
recording what an event hook was last told.

That the pattern existed six times is the older half of the finding, and this
project has written the rule down before: "one function because there are five
lists of exactly this shape, and five copies of a three-line rule is how two of
them come to disagree about what off means". Six copies of a read-modify-write
is how none of them acquires a lock.

## What the lock is, and the two things it is not

**`flock`, in `netcfgd-sys`.** Constraint 4 confines `unsafe` to that crate, and
`term.rs` already establishes that this is about the libc boundary rather than
about netlink. `netcfgd-host` reaches `netcfgd-sys` through `netcfgd-apply` and
`netcfgd-observe` already, so the new dependency edge is a name and not new code
in the binary.

**Not `std::fs::File::lock`,** which does exactly this and is unstable:
`file_lock` is not in 1.85, which is this workspace's `rust-version` and also
the rustc on this machine, a distribution build with no rustup. Taking it would
raise the floor for everybody compiling netcfgd from their distribution's
toolchain, which is a decision about who can build this rather than a way of
saving four lines.

**Not a lock file created with `O_EXCL`.** That outlives the process that made
it, so every user of one needs a staleness rule, and every staleness rule is a
guess about how long the work takes. A `flock` belongs to the open file
description and the kernel drops it when the last descriptor closes, which a
process killed mid-apply does for free.

**And the lock is on `owned.lock`, not on `owned.json`.** `owned.json` is
replaced by a rename, so a lock taken on it is a lock on an inode the next
writer unlinks -- which two writers can hold at once, each on a different inode,
believing they are excluded. The lock file is never renamed and never read; what
is locked is the name.

`update_owned` returns the error rather than swallowing it. Carrying on
unlocked is precisely the behaviour being replaced, and a caller that wants it
can have it by ignoring the result in its own words.

## Verified

A test with two threads that start together on a barrier and hold their change
open long enough that an unlocked implementation must interleave. With the lock
both records survive; with the lock line removed it fails every time, and says
so in the terms above:

```
  assertion `left == right` failed: an update was lost
    left: ["veth0"]
   right: ["veth0", "veth1"]
```

Threads are meaningful evidence here only because of which lock this is:
`fcntl` record locks are owned by the *process*, so a second thread would be
handed one immediately and the guard would guard nothing. `flock` is owned by
the open file description, so two `open` calls conflict whether or not they
share a process. `netcfgd-sys` has its own test for that property, because the
one above depends on it and would otherwise be quietly testing nothing.

## What this does not claim

**It is still not established that this is `qdisc.sh`'s intermittent failure.**
The mechanism is exactly right for the symptom -- a plan that keeps proposing
`qdisc.reset veth0` against a record that still claims the interface -- and the
brief's hypothesis predicted this interleaving before the code was read. But the
failure has not been caught in the act: the instrumentation added for it has
never fired, and the count is two failures in five container runs and none on
the host. Two earlier fixes for that failure were committed with explanations
that turned out to be wrong, and the correct response to that is to say what is
demonstrated -- a lost update, deterministically, in a test -- and what is
merely consistent.
