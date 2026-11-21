# 0330: a firewall rule may log, at ten a minute

Status: accepted
Date: 2026-11-21
Milestone: the firewall's layer one ([0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md))
Rests on: project.md 10.895, the inventory the holder asked for

## Context

0294 left logging out of the first vocabulary. The inventory the holder asked for
on 2026-11-21 put it first among what is missing, for a plain reason: a firewall
that drops in silence cannot be debugged, and an operator coming from iptables
writes `-j LOG` before anything else when a rule does not do what they meant.

## Decision

**`log = true` on a rule writes each matching packet to the kernel log, with
`netcfgd CHAIN/NAME: ` before it, at most ten a minute for the rule (a burst of
five).**

- **The log is a kernel rule of its own, ahead of the verdict's**: the same
  matches, `limit rate 10/minute burst 5 packets`, `log prefix "..."`, and no
  verdict. A `limit` in the verdict's own rule would end that rule past the rate,
  and every packet past ten a minute would fall through to the next rule instead
  of being dropped. Both kernel rules carry the written rule's name and digest, so
  the reader, the planner's comparison and `ncfg status` see a `log` row before
  the verdict's.
- **Rated and not configurable.** A rate somebody must choose before they may log
  is a reason not to log. Ten a minute says that a rule is being hit and by which
  address, and no flood can fill the disk through it.
- **Not beside `over` yet.** An `over` meter counts each time its rule is
  evaluated, so a log rule evaluating it again would count every packet twice and
  halve the threshold written. The compiler refuses the pair and says so. The way
  through is a packet mark set by the log's rule and matched by the verdict's,
  which needs a mark bit netcfgd reserves -- a decision about marks the inventory
  also lists as missing, so it is taken there rather than here.
- **`log` is in the digest only where set**, so no ruleset written before it
  changes digest. The document carries it as `log`, omitted when false; the
  renderer writes it back, and the window's rule dialog has a checkbox for it.

## Rejected

- **`log` in the verdict's rule, unrated.** One source hammering a dropped port
  would write a line per packet.
- **`NFLOG` to a group.** It needs a reader in user space (ulogd), which nothing
  on most machines runs; the kernel log is read by what is already there.
- **A configurable rate or prefix.** Can be added as keys later without changing
  what `log = true` means.
