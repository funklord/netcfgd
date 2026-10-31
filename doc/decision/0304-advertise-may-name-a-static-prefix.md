# 0304: advertise may name a static prefix

Status: accepted
Date: 2026-10-31
Milestone: the router side, with DHCPv6 (project.md 10.636)
Amends: [0009](0009-router-side-addressing.md)

## Context

`advertise { prefixes = [...] }` takes `@pd:` references only, and refuses
anything else with "never a prefix itself, which no config file can know".
That is 0009's indirection, and it is right for what 0009 wrote it for: a
delegated prefix is not known until the ISP's lease arrives, and a document
that carried one would stop being a pure function of the configuration.

It is wrong for a prefix the configuration does know. A ULA (`fd00:7::/64`), or
a static global prefix an ISP assigns for good, is written in the file already
-- as the interface's own address -- and refusing to advertise it leaves a LAN
with an IPv6 prefix and no way to tell its hosts. 0303's `range6` made that
visible: on such a LAN the hosts can never be told to ask. UniFi advertises a
static prefix, and the holder asked for what UniFi has (0303).

## Decision

**`prefixes` takes a literal IPv6 prefix beside `@pd:` references.** A word
that is not `@pd:` is a prefix, kept in the document as `static_prefixes`, so
the delegated references stay typed exactly as 0009 has them and nothing about
a delegated prefix changes.

- **A /64**, since that is what stateless autoconfiguration needs and what an
  advertised on-link prefix is for. Not link-local, not multicast.
- **On the interface**: the interface must hold a static address inside it.
  Advertising a prefix the router is not on hands hosts addresses with no route
  back, and is refused at compile time rather than discovered on the LAN.
- **Always resolvable**: a static prefix needs no lease, so an `advertise`
  with one starts radvd at once, and the planner compares it with what radvd
  announces exactly as it does a resolved delegation.

0009's purity argument is untouched: the document holds the prefix because the
configuration does.

## Alternatives considered

**Derive the prefix from the interface's static address, with no key.**
Rejected: an interface may hold several, and which to advertise is a choice the
operator makes; an advertisement nobody asked for is a policy nobody wrote.

**Any prefix length.** Rejected: a host autoconfigures only from a /64, so a
/56 advertised on-link configures nothing and reads as broken IPv6.
