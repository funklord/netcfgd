# 0299: a forward is reachable from inside, by default

Status: accepted
Date: 2026-10-30
Milestone: the router side, after port forwards (project.md 10.610)
Follows: [0298](0298-a-port-forward-is-translation-on-the-uplink.md)

## Context

0298's forward matches traffic arriving on the uplink. A host on the LAN that
connects to the router's public address -- the address a name in public DNS
points at -- arrives on the LAN interface instead, is not translated, and
reaches the router itself. And were it translated, the server behind would
answer the client directly across the LAN, from its own address rather than
the one the client dialled, and the client would drop the answer. Both halves
have to be fixed for "the same URL works at home" to be true.

The holder asked for hairpin NAT on 2026-10-30.

## Decision

**Every forward is reflected unless it says `hairpin = false`.** The point of
a forward is that its public address reaches the host; a forward that works
from everywhere but the network the host is on is the surprise, not the rule.
OpenWrt's default is the same, and its name for it is reflection.

A forward then becomes up to three kinds of kernel rule, each carrying the
forward's identity with its role: `name=wan0/web`, `name=wan0/web@reflect`
and `name=wan0/web@hairpin`.

- **Reflection**, in `prerouting`: arriving on any interface but the uplink,
  for the uplink's address, the same protocol and port, translated to the
  same host -- nft's `iifname != "wan0" ip daddr 203.0.113.1 tcp dport 443
  dnat ip to 192.168.1.10:8443`, measured. One rule per IPv4 address the
  uplink has: **the static ones the document gives it, and the ones observed
  on it**, so an uplink addressed by DHCP is reflected at its lease and the
  table is replaced when the lease's address changes, the way every other
  plan follows the machine. An uplink with no address yet has no reflection
  until it has one.
- **The return path**, in `postrouting`: leaving on the interface whose
  static IPv4 network contains the host, from that network, to the host and
  its port, masqueraded -- `oifname "lan0" ip saddr 192.168.1.0/24 ip daddr
  192.168.1.10 tcp dport 8443 masquerade`. Only clients on the host's own
  network need it; one on another segment is routed back through the router
  already. Where no interface in the document holds the host's network, there
  is nothing to scope the masquerade by, so it is not written and the plan
  says so.

The hairpinned server sees the router's LAN address as its client. That is the
cost of the return path, and the reason `hairpin = false` exists.

A forward's label is restricted to letters, digits, `-`, `_` and `.`, so the
identity's `/` and `@` cannot be in it.

## Consequences

- `ncfg_forward_rule_t` carries a kind; reflection the address it matches,
  the return path the network and the interface. The observation's forwards
  carry the same, and the planner compares the sets.
- The `postrouting` chain exists where an uplink is masqueraded or a return
  path is written.

## Alternatives considered

**`fib daddr type local`** in place of the observed address. Rejected: it
matches every address the router holds, its LAN address included, so a
forward of 443 would capture the router's own web interface from the LAN.

**Masquerading every connection translated by `ct status dnat`**, unscoped.
Rejected: it hides every client's address from every forwarded server,
including clients that did not need it.

**Off by default.** Rejected for the reason above; it is one word to turn
off.
