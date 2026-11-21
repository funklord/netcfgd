# 0333: an ICMP rule may name its types

Status: accepted
Date: 2026-11-21
Milestone: the firewall's layer one ([0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md))
Rests on: project.md 10.895, the inventory the holder asked for

## Context

A rule could match `protocol = "icmp"` or `"icmpv6"` and nothing finer. An input
chain that drops by policy then had two choices: accept every ICMP message, or
none -- and IPv6 does not work without neighbour discovery, while an operator
who wants ping answered need not answer redirects. `icmp type echo-request` and
`icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert }` are among the first
lines of any nftables router ruleset.

## Decision

**`icmp_type` on an `icmp` or `icmpv6` rule takes a name, a number, or a list of
either: `icmp_type = ["nd-neighbor-solicit", 136]`.**

- **Names are the protocol's**: `echo-request` is 8 for ICMP and 128 for ICMPv6,
  so names are read once the rule's protocol is known, whichever key is written
  first. The names are the sixteen an operator writes, as nft spells them; any
  other type is written as its number. A name the protocol does not have, a
  number past 255, or a type on a rule that is not ICMP's is refused at its line.
- **The document keeps numbers**, `icmp_types`, omitted when empty; the digest
  names them only where set, and the renderer writes them back by name where
  there is one.
- **One kernel rule per type**, matching the transport header's first byte, as
  nft writes `icmpv6 type nd-neighbor-solicit`. A rule has types or ports and
  never both, so the two share the expansion. The reader takes exactly that
  match and reports `icmp_type`, which the planner compares, `ncfg status` prints
  and the undo copy restores.
- **The window's rule dialog takes numbers**, which is what the document holds;
  its tooltip names the common ones.

## Rejected

- **ICMP codes.** A type is what operators match on; nobody has asked for a code.
- **An interval set** of types: see 0331's reason, which is 10.592's.
