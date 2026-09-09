# 0185: a daemon that has done work is the one to measure

Status: accepted
Date: 2026-09-09
Milestone: M8; the sixth audit, after writes, reads, execs, sockets and races

## The question

> now check the memory and resource errors too

## This one came back clean, and that is the finding

Unlike the five before it, the resource story was already in place and
mostly already argued:

* **The wire codec is bounded.** `MAX_LINE` is a megabyte, and `read_line`
  takes a `Read::by_ref(..).take(MAX_LINE)` *before* `read_until`, with the
  reason written above it: a control socket is reachable by anything that can
  open it, and a daemon holding `CAP_NET_ADMIN` being killed by the OOM killer
  is a denial of service with extra steps.
* **The event fan-out drops slow subscribers** rather than waiting: a bounded
  `sync_channel(64)` and `try_send`, with `retain` taking the failures out.
* **Connections are capped at 64**, so threads and descriptors are bounded by
  that. Measured: 20 connections take the daemon from 9 descriptors and 6
  threads to 69 and 26, and both return when they close.
* **The budgets are gated already.** `make check` runs `size`, `footprint`
  and `rss`; today `rss: netcfgd peak 4792 KB of 5120 limit`. A comment in
  `config.rs` claims the project gates on this, and it is true -- I went
  looking for the gate to correct the claim and found the claim correct.

## What was missing, and is the reason this has a decision at all

`make rss` measures a daemon **two seconds after it starts**. That is the
floor, not the risk. netcfgd runs for months, and what matters is whether
serving requests, reloading configuration and fanning out events give
anything back. **A leak of a kilobyte per reconcile is invisible at startup
and is 100 MB by the end of a quarter.**

Measured over 260 configuration reloads: RSS moved 10868 → 11004 → 11044 KB
on a debug build. The second burst was three times the size of the first and
added a fifth as much, which is an allocator settling rather than
accumulation. Descriptors and threads did not move at all.

`tests/live/steady_state.sh` pins that shape: three measurements, and the
comparison is between the last two, because the first burst legitimately
allocates. It asserts growth under an eighth of the working set rather than
zero -- a threshold of zero is a test people learn to ignore -- and asserts
descriptors and threads exactly, because those are counted and come back.

**It deliberately asserts no absolute number.** `make rss` owns the ceiling
and does it against a release build; this runs against whatever is built,
where a debug binary is twice the size. A ratchet in two places is a ratchet
that disagrees with itself.

## Two measurements of my own that were wrong first

Worth recording, because both produced a confident number that meant nothing.

**A fixture that could not play the part.** The concurrency probe in 0184 gave
netcfgd a stub `dhcpcd` and counted two clients started. netcfgd identifies a
running dhcpcd by asking its control socket which config it was started with;
a stub answers nothing, so netcfgd correctly declined to adopt it. The number
was the fixture's, not the code's.

**A measurement taken after the thing being measured had gone.** The
descriptor-exhaustion probe here read `/proc/<pid>/fd` *after* the client
process exited, and reported 9 descriptors under load -- the idle count. Two
runs and a control were built on it before the ordering was noticed. Reading
the count from inside the holding process gave 69.

## What is still open, stated rather than resolved

**Whether a failing `accept` spins.** The loop is
`for stream in listener.incoming() { let Ok(stream) = stream else { continue } }`,
which by construction retries immediately -- so a persistent `EMFILE` would be
a hot loop on a core. Driven against a daemon with `RLIMIT_NOFILE` of 24 and
40 clients queued, it burned **0 CPU ticks in five seconds**, so no spin was
observed; but the failing branch was not positively demonstrated either, and a
fix for a path nothing can reach is a fix nothing can check. Recorded here so
the next person starts where this stopped.

**A dump proportional to kernel state.** `request` collects a dump into
`Vec<Vec<u8>>`, which is bounded by what the kernel holds rather than by
netcfgd. On a laptop that is kilobytes; on a machine carrying a full routing
table it would not be. netcfgd is not a router and the budgets are set for the
machines it is for, so this is a limit rather than a defect -- but it is a
limit nobody had written down.
