# 0335: a rule may match the protocols netcfgd's own tunnels carry

Status: accepted
Date: 2026-11-22
Milestone: the firewall's layer one ([0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md))
Rests on: project.md 10.895, the inventory the holder asked for

## Context

A rule's `protocol` was one of `any tcp udp icmp icmpv6`. netcfgd itself builds
GRE, IPIP and SIT tunnels and IPsec (`xfrm`), and a machine whose input chain
drops by policy could let their packets in only with `protocol = "any"` from the
peer -- every protocol from that address, where the operator meant one. The
inventory listed `gre`, `esp` and `sctp` as missing.

## Decision

**`protocol` also takes `gre` (47), `esp` (50), `ah` (51), `sctp` (132), `ipip`
(4) and `sit` (41); `sctp` takes ports as tcp and udp do.**

- **`ipip` and `sit` are the tunnel modes' words**, the ones written in the same
  file as `tunnel { mode = "sit" }`, for IP protocol 4 and 41. nft prints them
  `ipencap` and `ipv6`, the names in `/etc/protocols`; `ipv6` as a rule's
  protocol would read as the address family, which a rule in an `inet` table
  already has two of. An ip6tnl tunnel carries the same two numbers, so the
  words cover it too.
- **The kernel match is nft's own**: `meta l4proto` and one byte, as for tcp, and
  sctp's destination port at the transport header's offset 2, as nft writes
  `sctp dport 3868` -- measured with nft 1.1.3 in a user namespace. The reader
  takes each number back to its word, the undo copy's reader is now the inverse
  of that word rather than a table of its own, and `ncfg status` prints it.
- **Appended to the enumeration**, so no stored value or digest moves.
- **The window's protocol list carries them**, and takes ports with sctp.

## Rejected

- **A protocol by number.** Every protocol an operator here meets has a word,
  and a number would be a second spelling of the six.
- **`ospf`, `vrrp`, `igmp`, `pim`.** netcfgd runs no routing daemon or VRRP
  yet; each is one more case when something it builds needs it.
- **`udplite`, `dccp`.** Nobody has asked.
