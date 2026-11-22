# 0336: a port forward may be limited to a source

Status: accepted
Date: 2026-11-22
Milestone: the firewall's layer one ([0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md)), port forwards ([0298](0298-a-port-forward-is-translation-on-the-uplink.md))
Rests on: project.md 10.895, the inventory the holder asked for

## Context

A port forward translated a port for anyone who reached it. The inventory found
`port_forward` with "no external source match": an operator who forwards ssh or
remote desktop to a host behind the router for one office has had to forward it
for the whole internet. OpenWrt's redirects carry `src_ip` for this, and the
OpenWrt routers are the next hardware netcfgd meets.

## Decision

**`from = "198.51.100.0/24"` on a `port_forward` limits it to that source: one
IPv4 address or network.**

- **Only the translation is limited.** A packet from elsewhere is not translated
  and meets the router's own input chain at that port, as it would with no
  forward at all; nothing is dropped on the forward's behalf, so the firewall
  stays the one place that says what is refused.
- **The forward and each reflection match `ip saddr`**, after the family, as nft
  1.1.3 writes `iifname "wan0" ip saddr 198.51.100.0/24 tcp dport 443 dnat ...`.
  The return path is unchanged: it carries only what a reflection let in. A host
  on the LAN reaches the forward through its reflection only when the source
  includes it, which is what the line says.
- **The compiler keeps the network**: host bits cleared and `/N` only where N is
  short of 32 -- the spelling the kernel reader prints, so the planner compares
  them as text. `/0` is refused as anyone, which is what leaving `from` out says;
  an IPv6 source is refused, a forward being IPv4.
- **Absent where unset**, in the document, the digest text and the observation,
  so no forward written before changes digest. The reader reports it, the
  planner compares it, `ncfg status` prints `from`, and the interface dialog's
  forward table has a column for it.

## Rejected

- **A list of sources.** Each would be one more forward rule and one more per
  reflection; one network covers the office case, and the key can take a list
  later as `port` does without changing what a string means.
- **Dropping what the source does not match**, in the forward chain. It would
  make the forward a second firewall, deciding what is refused somewhere an
  operator reading the firewall block does not look.
- **Two forwards of one port to two hosts by source.** The duplicate-port
  refusal stands: which one won would depend on the order of their names.
