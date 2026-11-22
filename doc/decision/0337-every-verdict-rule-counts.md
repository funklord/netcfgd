# 0337: every verdict rule counts, and `ncfg status` says what it matched

Status: accepted
Date: 2026-11-22
Milestone: the firewall's layer one ([0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md)), the installed firewall as rules ([0295](0295-what-identifies-an-installed-rule.md))
Rests on: project.md 10.895, the inventory the holder asked for; 10.901

## Context

"Is my rule matching anything?" is the first question anybody debugging a
firewall asks, and netcfgd could not answer it. `log` ([0330](0330-a-firewall-rule-may-log-at-ten-a-minute.md)) leaves a trace of
what a rule drops, at ten lines a minute, but nothing said how often an
`accept` fired or whether a `drop` had seen a packet at all. The inventory
(10.895) put counters second only to logging, and parked them on the reading
back that would make a count worth having.

## Decision

**Every verdict rule netcfgd writes carries a `counter` just before its verdict,
and `ncfg status` prints what each one matched.**

- **Always, not a key.** A counter costs the kernel two 64-bit adds per matched
  packet; a `counter = true` would be a choice nobody would make against it,
  and a rule that was not counting when the question came up cannot be asked
  afterwards.
- **Ahead of the verdict, after every match**, `over`'s meter included, so it
  counts what the rule decided rather than what it looked at. A log's rule
  (0330) carries none: its verdict's rule counts the same packets.
- **Written as nft 1.1.3 writes `counter`**, both members at zero, so a ruleset
  saved and loaded back with `nft -f` is still netcfgd's.
- **The count is read, never compared.** The reader takes the counter's
  members into the kernel rule and the planner compares only whether a rule
  carries one -- so a rule an older netcfgd wrote, with none, is replaced by the
  first plan after an upgrade, and a count is never a difference.
- **Counted since netcfgd last replaced the table.** The table is replaced in
  one transaction whenever the firewall changes, which zeroes every count; the
  count says so where it is shown.
- **Shown per kernel rule in `ncfg status`**, `accept ping protocol icmp type 8:
  3 packets, 252 bytes`, and per written rule in the window's firewall tab,
  summed over the kernel rules sharing its name. The observation carries
  `packets` and `bytes`, absent on a rule with no counter.

## Rejected

- **A `counter` key per rule.** The question it answers comes up after the
  fact, on a rule nobody thought to count.
- **Named counters** (`nft add counter`), which survive a rule's replacement.
  They would be a second kind of object in netcfgd's table, to name, read and
  clean up, for counts that last across an apply; resetting on a firewall
  change is what an operator watching the effect of the change wants anyway.
- **Comparing the count**, which would make every packet a drift.
