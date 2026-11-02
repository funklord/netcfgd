# 0307: a firewall rule may keep hours

Status: accepted
Date: 2026-11-03
Milestone: the router side (project.md 10.663)
Amends: [0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md)

## Context

Every consumer router has some form of "no internet for these devices after
ten on school nights". netcfgd's firewall (0294) had no way to say it, so the
operator's choice was a hand-written nftables table beside netcfgd's -- the
thing netcfgd exists to make unnecessary.

nftables can do it natively: `meta hour` and `meta day` read the kernel's
clock. That clock is UTC wherever nothing set the kernel's own zone, and nft's
userspace converts the hour into UTC and leaves the day alone, so its own
rules match the wrong day for an hour or more around midnight in most of the
world. And a conversion done once is wrong after the next summer-time change.

## Decision

A rule takes `hours = "22:00-07:00"` and `days = ["mon", ...]`, in the
machine's **local** time, because that is the clock the person writing the
rule is reading. A window that ends before it starts runs past midnight into
the next day.

**netcfgd expands the schedule into UTC pieces when it builds the rules** --
each piece a day (or every day) and an inclusive range of seconds, split and
moved wherever local midnight or UTC midnight falls -- and writes one kernel
rule per piece, `meta hour` swapped to network order and ranged, `meta day`
compared, exactly as nft encodes them. The pieces are in the rule's digest, so
a change of offset is a firewall that is no longer the document's.

**The loop puts a schedule back after a summer-time change by itself.** A
firewall replace is otherwise an apply's to make; this one is the clock's, and
it is recognised exactly: the document's firewall, given the pieces the
kernel holds, matches what is installed.

## What was rejected

**Gating the rule in the planner** -- installing it only inside its window,
from the loop's five-second tick. No new expression to encode, and every
schedule correct in local time by construction. But the rule then exists only
while netcfgd is running and planning, `ncfg plan` changes with the time of
day, and a daemon stopped at 21:59 leaves the children online all night. The
kernel holding the schedule is the property worth the encoding.

**nft's own conversion**: the hour and not the day, and once.

**A range that wraps past midnight, or `!=`**, which nft writes for a window
crossing midnight. Splitting into plain ranges reads back as one shape, and nft
1.1.3 refuses a wrapped range outright.

## The undo copy

A commit-confirm revert rebuilds the previous firewall from the kernel, and a
local schedule cannot be recovered from UTC pieces. So a rebuilt rule carries
its pieces (`utc_pieces`), the builder takes them as they are, and they digest
as the rules they were read from. A compiled document never has them.
