# 0300: a forward may name a reservation

Status: accepted
Date: 2026-10-30
Milestone: the router side, after hairpin (project.md 10.618)
Follows: [0298](0298-a-port-forward-is-translation-on-the-uplink.md)

## Context

0298 deferred one thing it called wanted: a forward's `to` naming a
reservation, so the host's address is written once, in its `host` block,
rather than twice -- once where the DHCP server hands it out and once where
the uplink forwards to it. Written twice, the two drift: the reservation is
moved and the forward goes on pointing at the old address, which is now
nobody's or somebody else's.

The holder asked for it on 2026-10-30.

## Decision

**`to` is an IPv4 address or the name of a reservation on any interface.**

```
interface wan0 {
	port_forward "web" { protocol = "tcp"; port = 443; to = "nas" }
}
interface lan0 {
	config = "192.168.1.1/24"
	dhcp_server { host "nas" { mac = "aa:bb:cc:dd:ee:01"; address = "192.168.1.10" } }
}
```

- **A name is a plain host name that is not only digits and dots** -- the
  reservation's own rule. Digits and dots stay an address, so
  `192.168.1.300` is refused as one rather than looked up as a name nobody
  could have meant.
- **Resolved by the compiler once every interface has been read**, since the
  reservation is on the LAN and the forward on the uplink and either may be
  read first. Exactly one must match: a name nothing reserves is refused
  rather than left forwarding nowhere, and one reserved on two networks is
  refused because either answer would be a guess.
- **The document carries both**: `to` is the address, which every rule, the
  hairpin's network lookup and the plan's warnings use unchanged, and
  `to_host` the name, absent for a forward written to an address. The
  renderer and the GUI write the name back, so a saved profile and a dialog's
  Save go on following the reservation.
- **The kernel rule and its identity digest are the address's**, as in 0298:
  naming the host changes no rule, and moving the reservation changes the
  forward's rule on the next apply like any other edit.

## Alternatives considered

**Resolving into `to` alone, keeping no name.** Rejected: the GUI's Save and
`ncfg profile save` would then write the address back, and the drift this
exists to prevent would return the first time either was used.

**A separate key, `to_host = "nas"`.** Rejected: two keys for one question,
and a block holding both would need a rule for which wins. One key whose value
is either kind reads as what it is.

**Looking only at the reservations of interfaces the forward could reach.**
Rejected for now: reachability is routing, which the compiler does not know,
and the ambiguity refusal already covers the case where it would matter.
