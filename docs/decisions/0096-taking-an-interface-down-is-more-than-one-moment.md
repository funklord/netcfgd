# 0096: taking an interface down is more than one moment

Status: accepted
Date: 2026-08-04
Milestone: the last recognised-and-never-run hook phase

## Context

[0063](0063-a-hook-phase-that-cannot-fire-says-so.md) made a phase nothing fires
say so in the plan rather than fail silently, and left one phase in that state
on purpose:

> `pre_down` and `down` fire at the same point in a plan. A phase whose only
> distinction is "before the addresses go" needs a teardown ordering netcfgd
> does not have yet.

Building it started by checking whether that was still true, and found something
larger than a hook. netcfgd's plan for disabling an interface was one action:

```
link.down eth0
```

On a real kernel, `ip link set t0 down` **flushes IPv6 and leaves IPv4 behind**:

```
before  10.9.9.1/24  fd00:9::1/64
after   10.9.9.1/24
```

So a disabled interface kept an address netcfgd had installed and still recorded
as its own, in one family and not the other, and nothing removed it. The
asymmetry is the kernel's — IPv6 addresses do not survive the link going down,
IPv4 ones do — and inheriting it means netcfgd's idea of what it owns depends on
which family the operator wrote.

The ordering a `pre_down` hook needs and the fix for that stale address are the
same change.

## Decision

**Disabling an interface is five steps, and the phases name them.**

```
pre_down    the interface still works: addresses, routes, all of it.
addr.del    what netcfgd installed, removed explicitly.
down        the link is still up and the addresses are gone.
link.down
post_down   nothing is left to stop.
```

`pre_down` is where a script that *needs the network* goes — unmounting a share,
telling a peer, flushing a queue somewhere else. That is the whole reason the
phase exists, and it could not do it while it fired at the same point as `down`.

**`down` has moved, and this is a behaviour change.** It used to run before
netcfgd removed anything, because netcfgd removed nothing. It now runs after the
addresses are gone and before the link goes. A `down` hook that needs to reach
the network must become a `pre_down` hook; a `down` hook that only touches the
local machine is unaffected. Both doc comments say so.

The alternative — leave `down` where it was and give `pre_down` the new slot —
keeps every existing hook working and makes the two names lie: `pre_down` would
run *after* the teardown started. Between a silent behaviour change and a
permanent misnomer, the phase names are the part that has to stay true, because
they are what an operator reads when deciding where to put a script.

**Only addresses netcfgd owns.** `Ownership::may_remove` already decides this
everywhere else and decides it here. An operator's static address on an
interface netcfgd is disabling is not netcfgd's to withdraw, and a daemon that
tidied it up would be a daemon that deletes configuration it did not make.

**Removal is explicit, not implied.** netcfgd could have relied on `link.down`
for the IPv6 half and issued `addr.del` only for IPv4, which is fewer actions on
most machines. It would also mean the plan does not say what it does, and the
plan is the thing this project asks operators to read.

## The gates

Three fixture tests and three breaks:

- no address removal at all — the state before this decision — fails the
  ordering test;
- removing anybody's address rather than only netcfgd's fails the ownership
  test;
- `down` no longer waiting for the withdrawal **passed**, at first.

That third one is the finding. The ordering test asserted positions in the
action list, and actions execute in list order — so deleting the dependency
changed no position and no assertion could see it. `project.md` already records
this shape ("a `depends_on` edge with no assertion on it is decoration") and the
test still had it. It now asserts the edge itself: the `down` hook depends on
the `addr.del`, and the `pre_down` hook does not. Then the break fails.

**Live**, under `unshare -rn` with a real kernel, three moments distinguished by
what each hook could see when it ran:

| moment      | address | link |
| ----------- | ------- | ---- |
| `pre_down`  | there   | up   |
| `down`      | gone    | up   |
| `post_down` | gone    | down |

A hook seeing the same thing at all three would be the old behaviour passing,
and it does not. The disabled interface is left carrying nothing of netcfgd's,
in both families, which is the stale-IPv4 fix in the same run.

## What this closes

Every one of the eleven hook phases now fires. 0063's machinery for reporting a
phase that cannot — the warning, and the test that a config using every phase
draws no warning — stays: it is what makes the *next* phase someone adds report
itself instead of going quiet, and the test now fails if a phase is added
without being wired up.
