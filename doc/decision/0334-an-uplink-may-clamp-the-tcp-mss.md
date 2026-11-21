# 0334: an uplink may clamp the TCP MSS

Status: accepted
Date: 2026-11-21
Milestone: M4's router side, ahead of the OpenWrt routers (project.md, *Live with it*)
Rests on: [0319](0319-flow-offload-is-a-flowtable-in-netcfgds-table.md)'s shape; project.md 10.895

## Context

A router whose uplink carries less than the LAN -- PPPoE's 1492 bytes, a tunnel's
less -- depends on path MTU discovery for every TCP connection it forwards, and
path MTU discovery depends on ICMP "too big" coming back. Plenty of sites drop it,
and the symptom is a page that loads partway and hangs. Every router distribution
clamps the MSS of forwarded SYNs for that reason (OpenWrt's `mtu_fix`, iptables'
`TCPMSS --clamp-mss-to-pmtu`). netcfgd routed, translated and firewalled, and
could not say this.

## Decision

**`clamp_mss = true` on an interface: a forwarded TCP SYN crossing it, either
way, has its MSS option set to what the route's MTU carries.**

- **A chain of its own, `mss`, in netcfgd's one table**, at the forward hook,
  priority mangle -- so the clamp is written before a filter at the same hook
  sees the packet -- policy accept, deciding nothing. Two rules an interface:
  `oifname "X" tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu`
  and the same with `iifname`. The expressions are the ones nft 1.1.3 writes,
  measured (project.md 10.895).
- **Part of the one transaction that replaces the table**, as NAT, the firewall,
  port forwards and flow offload are, so it is on the `nftables` op, in its
  inverse, and in the write audit's list of chains netcfgd may touch.
- **Read back exactly**: a rule in `mss` that is not the eight expressions as
  written is not netcfgd's clamp. The observation lists every interface a clamp
  rule names and counts the rules; the planner wants two per interface, so a
  rule deleted or left behind by hand is a difference, and is written again.
- **By name, whether or not the link exists**: a PPPoE uplink appears when it
  dials, and the rule matches it then.
- The document carries `clamp_mss` only where true; the interface dialog has a
  checkbox, and the client reads the key so a Save keeps it.

## Rejected

- **A fixed size** (`set 1452`). Right for one uplink and wrong when the route
  changes; `rt mtu` follows the route.
- **Clamping in the firewall's forward chain.** That chain is the operator's
  rules in their order; a clamp is not a verdict and has no place among them.
