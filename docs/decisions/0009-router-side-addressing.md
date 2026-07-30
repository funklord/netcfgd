# 0009: netcfgd configures, it does not serve

Status: accepted
Date: 2026-07-28
Milestone: model in M1, prefix delegation and PPPoE in M4, RA handoff in M4

## Context

Design §10.1 sets the bar for the embedded target as credibility against
`netifd`. A dual-stack consumer router is what `netifd` configures every day,
and four things it needs cannot be expressed in the model at all:

- **DHCPv6 prefix delegation.** `Dhcp6 { mode: Managed | OtherConf }` cannot
  say "the WAN requests a /56 and the LAN takes a /64 out of it". Without PD
  there is no IPv6 configuration for any consumer router, which is most of the
  reference target.
- **Router advertisements on the LAN.** The corollary: a delegated prefix that
  nothing advertises does nothing.
- **IPv4 forwarding.** Two configured interfaces are not a router until
  `net.ipv4.ip_forward` is set.
- **PPPoE.** Still how a large share of DSL and fibre services attach.
  `netifd` does it, NetworkManager does it, `InterfaceKind` has no variant for
  it.

Underneath all four is one unanswered question: does netcfgd configure the LAN
side of a router, or only the host's own attachment to a network? Every
individual feature request of this shape — a DHCP server, an RA sender, a
resolver, a NAT rule — is really asking that.

## Decision

**netcfgd configures; it does not serve.** It sets kernel state, requests
leases, and hands policy to daemons that answer other machines' requests. It
never answers one itself.

That rule is already what decision 0007 applied to DNS — model the policy,
delegate the resolver — and it resolves all four cases here without further
argument:

| Capability | In? | Why |
|---|---|---|
| DHCPv6-PD (requesting) | **yes** | client side; it is addressing |
| RA sending on the LAN | **policy yes, implementation no** | handed to odhcpd/radvd, like the DNS backends |
| `ip_forward` | **yes** | a sysctl over state netcfgd already owns |
| IPv4 masquerade | ~~no~~ **yes, in netcfgd's own table** | amended by [0022](0022-netcfgd-may-own-one-nftables-table.md); see below for the original reasoning |
| DHCPv4/v6 server | **no** | serving |
| PPPoE | **yes** | a link kind, implemented by pppd |

### Prefix delegation needs an indirection, not a value

PD is the one that changes something structural. The /64 that `br-lan` uses is
not known until the WAN's lease arrives, so an address on one interface
depends on a runtime value produced by another. Written naively that destroys
the property §2 exists to protect: the desired-state document would stop being
a pure function of the config files, and two compiles of the same config would
differ.

The design already has the pattern for this. `SecretRef` establishes that **the
document carries an indirection and never the value**, spelled `@secret:NAME`
in the DSL and typed in the document. Prefixes get the same treatment:

```
AddressSource =
  | Static    { ... }
  | Delegated { prefix: PrefixRef, suffix: string }   // new
  | Dhcp4     { ... }
  | Dhcp6     { mode, rapid_commit, prefix_delegation: PdRequest? }
  | Slaac     { ... }
  | LinkLocal

PrefixRef { source: string, index: u8 = 0, subnet: u16 = 0 }
PdRequest { hint: string?, length: u8? }
```

A separate `Delegated` variant rather than an `@pd:` string inside
`Static.address`, because the document should be typed even where the DSL
surface is a string — again as `SecretRef` already is.

Two consequences follow directly. §4 gains an ordering edge: the PD backend on
the source interface starts before any `addr.add` referencing that delegation,
and an unresolved reference blocks the action rather than failing the plan.
And renumbering — the ISP changing the delegated prefix — is an ordinary diff
producing `addr.del` then `addr.add` across every interface that derives from
it, with the existing `Lease` hook phase firing. It is a large plan, not a
special case.

The document stays byte-identical across compiles because it holds the
reference. The *plan* legitimately differs between runs, which was already
true of every DHCP address and is what `plan` is for.

### Why masquerade is excluded when forwarding is not

`ip_forward` is a sysctl over an interface netcfgd already manages. A
masquerade rule is an entry in a packet filter that something else owns —
`firewall4` on OpenWrt, `firewalld` or nftables directly elsewhere. Writing
into a ruleset netcfgd does not own means either fighting that tool over rule
ordering or requiring it to be absent. networkd's `IPMasquerade=` is the
worked example of how that goes.

A router therefore needs a firewall tool alongside netcfgd, and the `PostUp`
and `Lease` hook phases are where it gets driven. That is stated in the
documentation rather than discovered when someone's NAT stops working after an
unrelated ruleset reload.

## Consequences

**The netifd claim becomes defensible**, which it currently is not for any
IPv6 deployment. That claim appears in design §10.1 and in the §15 comparison
table, so it is load-bearing marketing as well as engineering.

**A new backend, `netcfgd-ppp`**, wrapping pppd, with its output parsed as
hostile input like every other backend under §6's fuzzing gate.

**RA handoff means a fourth delegated-daemon integration** after DHCP, wifi
and DNS. The shape is now familiar enough to be routine: policy in the model,
capability declared per backend, compile error when a backend cannot express
what the config asks for.

**`Delegated` is the first cross-interface dependency in the model.** The
planner's DAG already handles ordering between interfaces for masters and
members, so the machinery exists, but a reference that can fail to resolve at
apply time is new and needs its own fixture cases — in particular a plan
computed while the delegation is absent.

## Alternatives considered

**Support PD by recompiling when the lease arrives.** Rejected: it puts the
compiler in the runtime path, breaks the §4.3 seam that the embedded tiers and
the whole fixture-testing strategy depend on, and makes the nano tier — which
has no compiler — unable to be a router.

**Put the delegated prefix in the document at compile time.** Rejected for the
determinism reason above; it is the same mistake as inlining a secret.

**Leave router-side features out entirely and target hosts only.** Coherent,
and it would simplify the project. Rejected because design §10.1 has already
committed to the embedded target and to `netifd` as the comparison, and a
tool that cannot configure the device it is aimed at is not a smaller product,
it is an unfinished one.

**Include masquerade for convenience, as networkd does.** Rejected above. The
boundary rule is worth more than the one option: once netcfgd writes packet
filter rules there is no principled place to stop, and "configures, does not
serve" stops meaning anything.

## Amendment, 2026-07-30

The masquerade exclusion is amended by
[0022](0022-netcfgd-may-own-one-nftables-table.md). The reasoning above is
about ordering fights in a single shared ruleset, which is what iptables has;
nftables has named, independent tables, so netcfgd can own one outright without
reading or touching anybody else's. An nftables table turns out to be the same
kind of thing as the protocol-110 tag decision 0002 already relies on.

Nothing else in this record changes. "netcfgd configures; it does not serve"
still decides the other four rows, and 0022 draws the line one layer down:
netcfgd translates addresses, and never filters packets.
