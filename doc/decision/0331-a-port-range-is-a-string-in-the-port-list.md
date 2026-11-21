# 0331: a port range is a string in the port list

Status: accepted
Date: 2026-11-21
Milestone: the firewall's layer one ([0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md))
Rests on: project.md 10.895, the inventory the holder asked for

## Context

A firewall rule took single destination ports and nothing else, so passive FTP,
a game server's block of ports or an RTP range had to be listed port by port --
one kernel rule each, under the 256 one written rule may become. iptables writes
`--dport 6000:6010` and nftables `dport 6000-6010`, and both are among the first
things an operator moving a ruleset over writes.

## Decision

**`port` takes ranges beside single ports, a range written as a string:
`port = [27015, "6000-6010"]`.**

- **A string because the language has no range literal**, and `"6000-6010"` is
  how nft prints one. Two ports from 1 to 65535, the lower first; anything else
  is refused naming the rule's line. The lowering keeps one spelling, so the
  digest and the reader agree.
- **The document keeps them apart**: `ports` as before, and `port_ranges`,
  omitted when empty, so no document or digest written before changes. The
  renderer writes the singles and then the ranges.
- **One kernel rule per range, as per port**, matched by one `range` expression
  over the destination port -- what nft 1.1.3 writes for `th dport 6000-6010`. The
  reader takes exactly that and reports it as `port_range`, which the planner
  compares, `ncfg status` prints and the undo copy restores.
- **The window reads and writes them** in the ports field, `22, 6000-6010`, and the
  client hands them over beside the numbers, so a Save keeps them.

## Rejected

- **Two integer fields, `port_from` and `port_to`.** One range per rule, and a
  second spelling of a single port.
- **An nftables interval set** for all of a rule's ports. Compact, and 10.592
  already measured why the firewall expands to one kernel rule per value instead:
  interval sets are nftables' most intricate encoding, with a decoder to match.
- **Source ports.** Rarely what an operator means, and left for when somebody
  asks.
