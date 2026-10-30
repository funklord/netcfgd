# 0301: the LAN is answered by a DNS forwarder

Status: accepted
Date: 2026-10-30
Milestone: the router side, after reservation names (project.md 10.619)
Amends: [0009](0009-router-side-addressing.md), [0297](0297-a-dhcp-server-is-policy-served-by-dnsmasq.md)

## Context

0297 gave the LAN addresses and refused to guess its DNS server: the router's
own address is only right if something on the router answers the LAN, and
nothing did. So a netcfgd router's hosts were given whatever `dns` named --
usually a public resolver typed by hand, which bypasses the router's own
resolution, its search domains and its DHCP names -- or nothing, with a plan
warning saying they would resolve no names. A host on the LAN could not reach
another by the name it asked for its lease with.

The holder asked for the forwarder on 2026-10-30.

## Decision

**`dhcp_server { dns_forward = true }`: the same dnsmasq answers DNS on the
interface it serves, and forwards what it cannot answer to the resolvers the
router itself uses.** 0009's sentence holds as 0297 left it -- netcfgd
configures and dnsmasq serves -- and the table gains a row:

| Capability | In? | Why |
|---|---|---|
| DNS forwarding for the LAN | **policy yes, implementation no** | handed to the interface's dnsmasq, the one already serving its DHCP |

- **Upstream is the router's own resolution**: dnsmasq reads `/etc/resolv.conf`,
  which netcfgd's `dns` policy writes or another manager does, and re-reads it
  when it changes. A router resolving through systemd-resolved or a local
  dnsmasq forwards to it; one with a lease's servers forwards to those. No
  second list of upstream servers exists to drift from the first.
- **Hosts are offered the router**: with `dns_forward` and no `dns`, dnsmasq's
  own default applies and it offers the interface's address. A stated `dns`
  still wins, for an operator who wants the forwarder running and some hosts
  pointed elsewhere.
- **A host's lease name resolves**: dnsmasq answers for the names its DHCP side
  has handed out, which is what makes `ssh nas` work on the LAN.
- **`except-interface=lo`**, measured against dnsmasq 2.91: `interface=lan0`
  alone also binds `127.0.0.1:53` and `[::1]:53`, so it failed outright beside
  a resolver already on loopback, and two LAN instances would collide on it.
  With it, each binds only its interface's addresses, and two of them ran
  beside a loopback resolver. `listen-address` does not stop the loopback
  binding.
- **`domain-needed` and `bogus-priv`**, OpenWrt's defaults: a bare name and a
  reverse lookup of a private address are answered locally or not at all,
  never sent upstream.
- **The firewall is warned about, not opened**, as 0298 does for a forward: an
  `input` chain that drops with no rule accepting UDP 53 on the interface is a
  plan warning naming the rule to write. The same warning is given for a DHCP
  server's UDP 67, which 0297 had not.

A changed `dns_forward` is a restart, through the summary line every other
DHCP server setting is planned by.

## Alternatives considered

**A `dns_server` block of its own, beside `dhcp_server`.** Rejected for now: a
second dnsmasq on the same interface would need its own pid, log and lifecycle
for what one process does with two more lines of configuration, and a LAN that
wants DNS answered and no DHCP is rare enough to be a later key.

**Upstream servers listed in the policy.** Rejected: they would duplicate the
router's own resolution and drift from it, and the forwarder would then ignore
the search domains and routing the router has been configured with.

**Answering on every interface's address, `listen-address` style.** Rejected:
the LAN is the only side that should be answered, and an uplink that answers
DNS is an open resolver.
