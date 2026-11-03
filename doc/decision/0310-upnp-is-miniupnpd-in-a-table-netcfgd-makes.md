# 0310: UPnP and NAT-PMP are miniupnpd, in a table netcfgd makes

Status: accepted
Date: 2026-11-03
Milestone: the router side (project.md 10.667, 10.670)
Amends: [0283](0283-firewall-and-queuing-are-in-scope.md), in one table more

## Context

The holder asked for UPnP IGD and NAT-PMP on the router, on the condition
that the plan warns every time it is on (10.664 item 5). 10.667 planned it in
five steps and named miniupnpd (Debian 2.3.9, nftables build) as the daemon.
Three facts about that daemon decide the shape, and none of them could be
read off its documentation; each was measured in a vm with the image
`tests/hull/upnp/` builds:

1. **miniupnpd makes no nftables structure of its own.** Started on a
   configuration naming a table, it left the ruleset empty, and the first
   `AddPortMapping` failed with UPnP error 501. It adds rules to chains that
   must already exist. Debian's `nft_init.sh` makes them -- in an `inet
   filter` table whose forward chain has **policy drop**, which on a router
   netcfgd runs would drop every forwarded packet that did not match a
   mapping.
2. **A rule it adds cannot get past netcfgd's own firewall.** A packet is
   dropped if any base chain on its hook drops it, and an accept in another
   table does not help. With netcfgd's forward chain at `policy drop`, a
   mapping miniupnpd made in its own table was refused; with `ct status dnat
   accept` in netcfgd's chain, the same mapping carried a connection from the
   uplink side to the LAN host.
3. **It leaves its mappings behind when it stops.** After SIGTERM the DNAT
   rule and the forward accept were still in the table. A stopped miniupnpd
   would leave ports open to hosts with nothing renewing them.

## Decision

- **netcfgd makes the table, `inet netcfgd_upnp`, before it starts
  miniupnpd and deletes it after stopping it.** Three base chains -- forward
  (filter), prerouting and postrouting (nat) -- every one `policy accept`,
  and nothing in them: miniupnpd is told the table and the three chains by
  name (`upnp_table_name`, `upnp_forward_chain`, `upnp_nat_chain`,
  `upnp_nat_postrouting_chain`) and **adds its rules to the hooked chains
  directly**, which was measured -- the mapping was made there and carried a
  connection. So there are no jumps and no inner chains, and netcfgd writes
  only constructs it already writes for its own table. The table adds
  mappings and drops nothing. It is netcfgd's by name and by lifetime, so it
  is not a stranger's table to report (10.539).
- **netcfgd adds no accept to the operator's firewall**, which is 0298's rule
  for port forwards held to again. The firewall gains a way to say it --
  a rule matching connections a translation produced, `ct status dnat` --
  and the plan names that rule when UPnP is on and the forward chain drops by
  policy without one.
- **The language is `global { upnp { lan = [...]; uplink = "..." } }`**, as
  10.667 set it: the interfaces it listens on, and the one it maps on.
  `secure_mode` is always on, so a client maps ports only to itself, and
  NAT-PMP/PCP is on the same switch as UPnP. Refused without masquerade on
  the uplink, since a mapping with no translation is a forward to nowhere.
- **The plan warns every time it is on**, the holder's condition: any device
  on those networks may open a port on this router without asking, and a
  compromised one can expose itself or anything behind it.

## Consequences

- **A second table netcfgd writes.** 0022 gave netcfgd one table and 0283
  kept that while widening what it holds; `ncfg_nft_writes_only_our_table`
  enforces it on every transaction. It admits `netcfgd_upnp` by name, for the
  table, its three chains and its deletion only -- netcfgd writes no rule in
  it, the rules being miniupnpd's.
- **Not a NAT conflict.** The report 0022 built names another table with a
  nat chain on netcfgd's hooks, because two translations double-translate.
  `netcfgd_upnp` has two such chains, and a mapping is a translation netcfgd
  arranged; it is named as netcfgd's, not reported.
- **netcfgd does not read the mappings back as its own.** What miniupnpd put
  in the table is shown by `ncfg status` (10.667 step 4) as what it
  is -- leases a client asked for -- and never compared against the document.
  netcfgd's own table is replaced on every apply; this one is made once, when
  the backend starts, and is not, or every apply would drop every mapping.

## Alternatives considered

**Debian's `nft_init.sh`.** Rejected by measurement 1: its forward chain
drops by policy, so running it would turn a router into one that forwards
only what UPnP mapped.

**miniupnpd's chains inside netcfgd's own table**, so that its accepts sit
in netcfgd's forward chain and no `ct status dnat` rule is needed. Rejected:
netcfgd replaces its table on every apply and refuses rules it did not write
(0298's observer), so either every apply would erase the mappings or the
table netcfgd owns would hold rules it cannot read -- the one table whose
whole contents netcfgd vouches for.

**An implicit `ct status dnat accept`, as OpenWrt's fw4 writes.** Rejected
for 0298's reason: it accepts every connection any table translated, docker's
included, in a chain the operator did not write it in.
