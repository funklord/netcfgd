# 0298: a port forward is translation on the uplink

Status: accepted
Date: 2026-10-30
Milestone: the router side, after reservations (project.md 10.609)
Amends: [0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md)

## Context

0294 left "nat redirection" out of layer one's first version, and 0284 had
reopened port forwards from 0022's "not derivable from addressing". A router
netcfgd runs can masquerade its LAN, serve it DHCP and reserve a host's
address (10.605), and still cannot let one inbound connection reach that host
-- the setting a home router is asked for after the range itself.

The holder asked for port forwards on 2026-10-30.

## Decision

**A port forward is address translation, so it belongs where `nat` does: on
the interface the traffic arrives on.** 0022's own test was whether a rule's
content is derivable from addressing, and a forward is the inverse of the
masquerade the same interface already carries -- one destination rewritten
instead of one source. It is not a filter rule and does not go in `firewall`.

```
interface wan0 {
	nat = true
	forwarding = true
	port_forward "web" {
		protocol = "tcp"
		port = 443
		to = "192.168.1.10"
		to_port = 8443
	}
}
```

- **Labelled, as a firewall rule and a reservation are**: the label is the
  forward's identity, unique within its interface, and what the plan names.
- `protocol` is `tcp` or `udp` and required: a forward of "any" protocol has
  no port to match.
- `port` is the one the uplink listens on, 1 to 65535; one per forward, so a
  plan line says what moved.
- `to` is one IPv4 address, not loopback, multicast, broadcast or
  unspecified -- the host's network is another interface's, so whether it is
  a network or broadcast address there is not checked. IPv4 only: IPv6 has no
  translation to undo, and a host reached over IPv6 needs a firewall rule
  instead.
- `to_port` defaults to `port`.
- **Two forwards of one port and protocol on one interface are refused**: the
  first would win and the second would be a rule that never matches.

### What it becomes

A fourth chain in netcfgd's one table, `prerouting`, of type `nat` at the
`prerouting` hook with `dstnat` priority (-100) -- written only when some
forward exists, so a machine with none has the table it had. Each forward is
one rule, encoded as nft 1.1.3 encodes `iifname "wan0" tcp dport 443 dnat ip
to 192.168.1.10:8443`, measured with `--debug=netlink`:

```
meta load iifname => reg 1 ; cmp eq reg 1 "wan0"
meta load l4proto => reg 1 ; cmp eq reg 1 6
payload load 2b @ transport header + 2 => reg 1 ; cmp eq reg 1 443
immediate reg 1 192.168.1.10 ; immediate reg 2 8443
nat dnat ip addr_min reg 1 proto_min reg 2 flags 0x2
```

and carries 0295's identity comment, `name=wan0/web sha256=...`, the digest
over netcfgd's own text of the forward. The whole table is still replaced in
one transaction (0022, 0294), so a forward added never half-applies and the
firewall and masquerade are carried through it unchanged.

### What it does not do, said as warnings

- **Forwarding.** IPv4 forwards a packet by the setting of the interface it
  arrives on, so a forward on `wan0` needs `forwarding = true` on `wan0`. A
  plan warning says so where it is missing.
- **The firewall.** A `forward { policy = "drop" }` drops the translated
  traffic like any other. netcfgd does not add a hidden accept: a rule nobody
  wrote is the opposite of layer one's named rules. A plan warning names the
  forward and the accept rule that would let it through, unless the forward
  chain already has an accept rule naming its address.

## Consequences

- The `nftables.replace` op gains the forwards; its inverse is the observed
  ones, so undoing it restores what was installed.
- The observer decodes the `prerouting` chain the way it decodes the filter
  chains, refusing a rule that is not as netcfgd writes them; a refused rule
  is a difference, so a hand edit there is replaced on the next apply.
- The GUI's interface dialog has no table for forwards, so the client names
  them unmodelled and the dialog refuses to save over them (10.606).
- `ncfg_nft_writes_only_our_table` admits the new chain name and the `nat`
  and `immediate` expressions it needs; it still refuses anything naming
  another table.

## Alternatives considered

**In `firewall`, as a `dnat` action.** Rejected: the firewall is the
host-private filter layer 0294 named, and a forward is not a filter -- it
rewrites where a packet goes. Putting it there would make a document with no
firewall unable to forward a port.

**An implicit `ct status dnat accept` at the head of the forward chain**, as
OpenWrt's fw4 writes. Rejected for now: it accepts every connection any table
translated, docker's included, and it is a rule in the operator's chain they
did not write. A warning that names the rule to write keeps the chain theirs.

**`to` naming a reservation by its host name**, so an address is written
once. Wanted, and deferred: it is a reference across interfaces that the
compiler would resolve, and is a separate change from the translation itself.

**Hairpin NAT** -- a LAN host reaching the forward through the uplink's public
address. Not done: it needs a source translation of the LAN's own traffic and
is a separate change.
