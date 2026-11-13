# 0319: flow offload is a flowtable in netcfgd's table, asked for globally

Status: accepted
Date: 2026-11-13
Milestone: M5 (routers)
Extends: [0283](0283-firewall-and-queuing-are-in-scope.md), [0318](0318-the-table-and-the-rules-are-the-hosts.md)

## Context

A router's forwarding is its CPU's work, packet by packet, until the kernel is told it
may skip the stack for a connection already established. That is a **flowtable**: an
established TCP or UDP flow, once added to it, is forwarded at the ingress hook of the
devices the flowtable names, past routing lookup, netfilter's later hooks and the qdisc
-- in software, or handed to the switch silicon where the driver can take it
(`flags offload`). On a two-core Cortex-A53 router it is commonly the difference between
a gigabit WAN and a fraction of one.

OpenWrt offers it through `firewall4`: `flow_offloading` and `flow_offloading_hw` in
the firewall's defaults, both off unless set. **`kmod-nft-offload` is in the default
image** of 25.12 -- read from the release manifests of `armsr/armv8` and
`mediatek/filogic`, 2026-11-13 -- so every router netcfgd targets can do it in
software, and Filogic's MediaTek parts in hardware. And the router guide tells a person
to stop `firewall` once netcfgd's NAT and `firewall` block do its work (0318). **So a
router whose owner had offloading on loses it under netcfgd**, silently, and nothing in
netcfgd's document could ask for it back.

0283 put the firewall in scope in full, on the holder's word. A flowtable is part of
what a firewall tool does on a router, and it lives in nftables, so it belongs in the
one table netcfgd already owns.

## Decision

**`global { flow_offload = "software" }` or `"hardware"`; absent is off.** Global, as
fw4's two options are, because a flowtable is one object for the forwarding path rather
than a property of one interface -- and because a router written the way the guide
writes one has `nat = true` and no `firewall` block, so the setting cannot require one.
Absent follows the default, which is off, as fw4's is; a choice is stored only where one
was made (working-practice, *a config file records choices*).

**What is written, in netcfgd's table and nowhere else:**

- a flowtable `offload`, hooked at `ingress`, priority `filter`, whose devices are the
  links of every interface with `forwarding = true` or `nat = true` that **exist** when
  the table is written -- a flowtable naming an absent device is refused by the kernel,
  so a device that appears later is a difference the next pass repairs, as 0318 makes
  every difference in this table;
- with `"hardware"`, the flowtable carries `flags offload`;
- a base chain `offload` at the `forward` hook, priority `filter`, policy `accept`,
  holding a rule per protocol: `meta l4proto tcp flow add @offload` and the same for
  `udp` -- two rules rather than fw4's one over an anonymous set, which would be a set
  object in the table for a comparison of one byte. The kernel moves a flow only once
  its conntrack entry is established, so no state match is written.

**It filters nothing.** The chain's policy is accept and its one rule moves a flow to
the fast path; a verdict of accept in one table does not override a drop in another, so
a `firewall` block's `forward` chain, or a neighbour's, still decides what is allowed.
It is the same table and the same atomic replacement, so 0318's drift repair covers it.

**Hardware a driver cannot do is a refusal of the whole table, named.** The kernel
refuses `flags offload` on a device whose driver has no flow offload (`EOPNOTSUPP`),
and the table is one transaction, so the NAT would go with it. The plan therefore says,
before the apply, which devices the hardware flowtable names; the apply's failure names
the construct and the kernel, which is 0287's `unsupported` standing in words.

## Consequences

- The document gains one global key, the observation a flowtable read back from the
  kernel, and the `nftables.replace` op the offload mode and device list it writes. The
  schema witnesses move by a minor version: the key is additive and a document without it
  means what it meant.
- **Testable in hull, the software half**: on `hull-armsr` a connection through the
  router shows `[OFFLOAD]` in conntrack, and with the key removed it does not. **The
  hardware half needs the silicon** -- a MediaTek PPE -- and is the first thing on the
  list of what a real router is for.

## Alternatives considered

- **Per interface** (`offload = true` in an `interface` block). A flowtable spans
  devices, and a flow is offloaded between two of them; per-interface keys would have to
  agree, and the useful answer is always "every forwarding interface".
- **Inside the `firewall` block.** fw4 keeps it in its defaults, but netcfgd's firewall
  block, present, writes three filter chains (0294); requiring one to get offloading
  would change a router's filtering to change its speed.
- **Leaving it to fw4.** The guide stops fw4, and fw4's flowtable lives in fw4's table,
  which `fw4 flush` and netcfgd's own table do not share.
