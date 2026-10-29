# 0297: a DHCP server is policy, served by dnsmasq

Status: accepted
Date: 2026-10-29
Milestone: the router side, after 802.11ax (project.md 10.601)
Amends: [0009](0009-router-side-addressing.md)

## Context

0009 drew the router side's boundary as "netcfgd configures; it does not
serve", and its table answered **DHCPv4/v6 server: no**. Router
advertisements were answered differently in the same table -- **policy yes,
implementation no**, handed to radvd -- and that is what netcfgd built.

Since then netcfgd has come to run the rest of a router: access points with
station lists, steering and every width up to 160 MHz, NAT and a firewall in
its own table, router advertisements and delegated prefixes. **A station that
associates with a netcfgd access point is given no address**, and the tree
says so in its own words (project.md 10.95, "netcfgd serves no DHCP ... so
an address is necessary and not sufficient"). The README's claim -- that
netcfgd configures the router as fully as the laptop -- had one row missing,
and it was this one.

The holder asked for the amendment on 2026-10-29.

## Decision

**A DHCP server is the same kind of thing as a router advertisement**: netcfgd
decides what is offered on an interface and hands it to a daemon that answers
the requests. It never answers one itself, so 0009's sentence stands as
written -- netcfgd configures, and dnsmasq serves -- and only the table row
moves:

| Capability | In? | Why |
|---|---|---|
| DHCPv4 server | **policy yes, implementation no** | handed to dnsmasq, as RA is to radvd |
| DHCPv6 server | **no, for now** | RA and SLAAC already address the hosts; stateful DHCPv6 is a later question |

### What the policy is

`dhcp_server { range, lease, dns }` inside an `interface` block:

- **The interface must have a static IPv4 address**, which is the network
  served and the router offered. An interface addressed by DHCP or a
  delegation has no address the document knows, and a server on it would be
  offering a network nobody wrote down; refused at compile time.
- **`range`** defaults to the 100th to the 249th host of that network, which
  is OpenWrt's default and leaves the low addresses for things given static
  ones. Refused where the network is too small for the default, and where a
  stated range is outside it.
- **`lease`** defaults to 12 hours, OpenWrt's default.
- **`dns` is never guessed.** Measured against dnsmasq 2.91 with its DNS side
  off (`port=0`): it offers no DNS server unless one is named. netcfgd does
  not invent one -- the router's own address is only right if something on
  the router resolves, and the upstream servers are only right if the LAN may
  reach them -- so a `dhcp_server` with no `dns` is a plan warning saying the
  hosts it serves will be given none.
- The router offered is the interface's own address, which is dnsmasq's
  default and what a router is.

### What serves it

**dnsmasq**, one instance per interface, DHCP only: `port=0`, so it is never
also a resolver and cannot collide with a `dns_mode = "dnsmasq"` delivery;
`bind-interfaces`, measured to let two instances serve two interfaces at once;
`dhcp-authoritative`, so a client asking for an address from another network
is told no at once rather than left to time out. Its configuration, pid file,
log and **lease file** live under netcfgd's run directory, `/run/netcfgd/
dhcp-server/<interface>.*`, for 0026's reason -- and the lease file is the
greppable record of who has which address, which the aims ask `/run` to be.

udhcpd, odhcpd and Kea take entirely different configuration and are not
implemented; a later `backend` key names one, as `advertise.backend` does.

## Consequences

- An eleventh backend kind, `dhcp_server`, through every switch the taxonomy
  runs: start, stop, liveness by the pid file and the generated
  configuration's path in the daemon's own argv, adoption, and the ledger's
  per-backend rows.
- A changed policy is a restart: dnsmasq re-reads its hosts and leases on
  `SIGHUP`, not `dhcp-range`. Clients keep their leases across it, since the
  lease file is kept.
- 0040's "there is no hostname to show" changes from a fact to a missing
  feature: the lease file has the name a client sent. Reading it is later
  work, recorded here so it is not rediscovered.

## Alternatives considered

**Serve DHCP from netcfgd itself.** Rejected for 0009's reason, unchanged: a
program that answers other machines' requests has a parser and a timer loop
facing the network, and that is the surface this project avoids.

**Default `dns` to the router's own address.** Rejected: on a router whose
resolver listens on loopback only, which is the common default, every host on
the LAN would be given a DNS server that does not answer, and a broken
resolver reads as "the internet is down".

**udhcpd, for its size.** Not rejected, deferred: dnsmasq is already a
package this project names (`dns_mode`), is on every distribution and on
OpenWrt, and was measured; udhcpd is a later `backend` value.
