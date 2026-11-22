# 0338: the packet mark's top bit is netcfgd's, so a guard may log

Status: accepted
Date: 2026-11-22
Milestone: the firewall's layer one ([0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md)); logging ([0330](0330-a-firewall-rule-may-log-at-ten-a-minute.md))
Rests on: project.md 10.895, the holder's answer of 2026-11-22; 10.904
Supersedes: 0330's "Not beside `over` yet"

## Context

`log = true` (0330) is a kernel rule of its own ahead of the verdict's, because
a `limit` in the verdict's rule would end that rule past the log's rate. An
`over` meter counts every time its rule is evaluated, so the log's rule and
the verdict's rule each counting it would see every packet twice and halve the
threshold written. 0330 refused the pair. That left the SSH guard -- the one
rule whose drops an operator most wants to see -- unable to log.

One rule tells the next something through the packet mark. A mark is shared
with policy routing (`rule { fwmark }`) and WireGuard's `fwmark`, so using one
bit is a reservation, and the holder made it: 0x80000000.

## Decision

**netcfgd reserves the packet mark's top bit, `0x80000000`, for its firewall,
and a logged `over` rule counts its meter once, in the log's rule.**

- **The log's rule**: the matches, `meta mark set meta mark & 0x7fffffff`,
  the meter, `meta mark set meta mark | 0x80000000`, then the log's own
  `limit` and `log`. Cleared ahead of the meter, so a packet arriving with
  the bit set says nothing; set ahead of the log's rate, so a log line skipped
  past ten a minute is not a verdict skipped.
- **The verdict's rule**: the same matches, `meta mark & 0x80000000 ==
  0x80000000` in the meter's place, `meta mark set meta mark & 0x7fffffff`,
  the counter and the verdict. Cleared again so nothing after netcfgd's chain
  sees the bit; a packet the meter let through never had it.
- **Written as nft 1.1.3 writes those three statements**, measured with
  `nft --debug=netlink`: load, `bitwise` (AND, XOR), store, the mark host order
  in the register. A ruleset saved and loaded back is still netcfgd's.
- **Read back strictly.** The reader takes the mark in exactly those two
  shapes and refuses any other bit, a store elsewhere, or a mark in a rule
  that is neither -- naming the mark. Both rows observe as `marked`, which the
  planner compares, and `ncfg status` shows the verdict's row as `over, as its
  log counted`.
- **The reservation is enforced where a document could take the bit**: a
  routing rule's `fwmark`, or an `fwmask` written naming the bit, and a
  WireGuard `fwmark` are refused at compile time. An absent `fwmask` is the
  kernel's whole word and is not refused: it reads the bit only to require it
  clear, and the bit is only ever set between two of netcfgd's rules.
- **Proved on a kernel**: `tests/live/firewall.sh` pings five times through a
  logged guard of two a minute and gets two replies. Counting the meter in
  both rules, the shape 0330 refused, gives one.

## Rejected

- **The meter in both rules, its threshold doubled to compensate.** A
  token bucket's burst and rate do not halve evenly, and a log line skipped by
  the log's rate would still have taken a token.
- **A named counter or a second set** to carry the answer. A set update per
  packet costs more than a mark and is a second object to name and clean up.
- **`ct mark`.** It lasts as long as the connection; the answer is about one
  packet.
- **A configurable bit.** Nobody would choose one before needing it, and a
  document that moves it breaks every saved ruleset.
