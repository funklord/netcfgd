# 0184: an apply is one at a time

Status: accepted
Date: 2026-09-09
Milestone: M8; the fifth audit, after writes (0180), reads (0181), execs (0182)
and sockets (0183)

## The question

> now check the timing and race errors too

## What serialised an apply: nothing

`FileLock` has been in the tree since the ownership record needed one, and
that was its only caller. **An apply -- observe, plan, act -- had no lock at
all**, so two of them could run against one machine with each planning against
a state the other was in the middle of changing. The pair that meets in
practice is an operator's `ncfg apply` and the daemon's own reconcile, which
runs every few seconds.

Measured, five rounds of two simultaneous applies over four addresses and two
routes: **five failed actions, one per round.**

    FAIL route.add r0  routes: 10.98.0.0/16 via 10.13.1.254 (was <absent>)

Every one a route the other apply had installed between this one's observation
and its action.

## Two things the measurement taught that the first attempt got wrong

**The first probe measured its own fixture.** It gave netcfgd a stub `dhcpcd`
and counted two clients started -- and that number was not the race. netcfgd
recognises a running dhcpcd by asking its control socket which config file it
was started with (0143); a stub answers nothing, so netcfgd correctly declined
to adopt it and started its own. Two applies would have done that with no race
at all. The finding survived because the second probe used netlink alone,
where nothing is being faked.

**The lock in the wrong place fixes nothing.** Taken when the executor is
built -- which is after the plan is computed -- it serialised the actions and
left the failure exactly where it was, because the second apply had already
planned. `apply_lock()` is therefore taken before the observation, in
`command_apply` and in the daemon's `executor()`, and the executor carries it
for as long as it lives.

## Why not tolerate `EEXIST` instead

It would have been one line, and it would have been wrong. Adding an address
that is already there is not an error -- `add_address` uses `NLM_F_REPLACE` --
while `add_route` uses `NLM_F_CREATE` alone, so an existing route is `EEXIST`.
But `EEXIST` for a route means **the key** exists, not that its gateway is what
netcfgd asked for: the kernel matches on destination, table, tos and priority.
A tolerant add would report success over a route pointing somewhere else,
which is this week's other four decisions in one line.

## Bounded, and what happens when it is not free

`exclusive_within` waits with `LOCK_NB` and gives up after thirty seconds,
naming the file. The blocking `exclusive` was the wrong shape here: it guards
a read-modify-write that takes microseconds, whereas an apply holds this for
as long as a hook takes, and a hook is an operator's shell script. **Waiting
for ever on that turns one stuck apply into a daemon that never reconciles
again.**

## What is checked

`tests/live/apply_race.sh` runs the pair five times and requires no failed
action, the full configuration afterwards, and the lock file to exist --
because two applies that both refused to start would also report zero
failures. Sabotaged by removing the lock, the count goes back to five.

## What was looked at and found sound

* **Sleeps**: nine, all bounded polls or a fixed tick. The `ETXTBSY` retry in
  `hooks` is linear and bounded by design; `dhcpcd`'s stop confirmation polls
  to a deadline (0179).
* **A half-written configuration**: the watcher has no debounce, so a
  truncate-then-write from an editor can be read mid-write. Measured -- the
  address stayed up throughout, and the completed file was picked up
  afterwards. The document that does not compile is not acted on, which is
  what 0127's "netcfgd is the only writer" leaves to chance for a file an
  operator edits by hand.
* **Pid recycling**: already answered. A pid file is never trusted alone; the
  process's own `/proc/<pid>/cmdline` has to carry a marker netcfgd composed
  (0065, 0140).
