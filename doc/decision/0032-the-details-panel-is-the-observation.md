# 0032: The details panel is the observation

Status: accepted
Date: 2026-07-31
Milestone: M7

## Context

Tier 2 is the settings panels (design section 9.5): profile editing, static IP,
per-connection options. The first thing any of them opens with is the Details
tab -- the addresses, gateway, routes and nameservers a device actually has --
and until now that was empty, because `Device.Ip4Config` was `/`, NM's spelling
for "there is no object here".

## Decision

**`IP4Config` and `IP6Config` are projections of netcfgd's observation, and
nothing else.**

Every property is read from what `ncfg status` would print. That is the same
discipline the device objects already follow, and here it has a specific
payoff: a desktop panel and the command line cannot disagree about what the
machine is doing, because there is one answer and two renderings of it.

Two things netcfgd does not have a field for are derived rather than invented:

**The gateway.** netcfgd has routes; NM has a gateway. They are the same fact --
the gateway is the next hop of the default route -- so it is computed rather
than stored, and a machine with no default route reports no gateway rather than
a stale one.

**The nameservers.** Taken from the *applied* DNS rather than from the
configuration. Decision 0007's whole point is that those can differ per scope,
and what a panel shows should be what resolution actually uses.

## Two objects, not one with a flag

NM's two interfaces are not the same shape. `Addresses` is `aau` on the IPv4
object and `a(ayuay)` on the IPv6 one -- an IPv6 address does not fit in a
`u32` -- and `WinsServers` exists on one and not the other. A single Rust type
cannot serve both, and a type that pretended to would be serving one of them
wrongly. So there are two, over a shared inner helper that does the parsing and
the filtering.

## The deprecated properties are implemented anyway

NM marks `Addresses`, `Routes` and `Nameservers` deprecated in favour of the
`*Data` forms, and still serves them, because clients written against the old
API are still installed. Serving only the modern half would work with `nmcli`
and fail with whatever has not been updated since 2015, which is exactly the
audience an NM shim exists for.

They are a packed integer format, and the packing is the kind of thing that has
two plausible answers and one right one: the four octets in wire order, read
back as a **native-endian** `u32`, so 10.0.125.37 is 628949002 on a
little-endian machine. That is not a byte-order conversion so much as the
absence of one. It was taken from a running `NetworkManager` 1.52 -- which
reported exactly that number for an address this machine held, and 16777226 for
the gateway 10.0.0.1 -- rather than reasoned out, and the live test asserts the
packed form against the address a panel shows so the two cannot drift apart.

## The test tried to rewrite the machine's resolver configuration

Worth recording because of how close it came. The DNS checks needed netcfgd to
have *applied* DNS, so the fixture grew a `global { dns { ... } }` block -- and
`tests/live/nm.sh` had never set `NCFG_RESOLV_CONF`. A network namespace is not
a mount namespace, so `/etc/resolv.conf` inside `unshare -rn` is the real one.

The write failed, and only for a reason nobody designed: the user namespace maps
the invoking user to uid 0 inside, but the real root that owns
`/etc/resolv.conf` is unmapped, so there was no permission to write it. The
host's file was checked afterwards and is untouched.

The environment variable exists precisely for this -- `netcfgd-apply` says so in
as many words, "which a test very nearly did" -- and the fixture now sets it.
Every live test that applies DNS needs to, and this one did not because it had
never applied any.

## What tier 2 still needs

Static addressing in the settings dictionary, in both directions: a panel
showing a profile's *configured* address (not just the applied one), and
writing one back. That is the next commit, and it is the half that touches the
write path again.

After that, per-connection options -- MTU, metered, autoconnect priority --
which are a field-by-field mapping with no new mechanism behind them.
