# 0064: A lease is an address netcfgd did not install

Status: accepted. The udhcpc defect named at the end was fixed by
[0065](0065-udhcpc-needs-a-script-and-netcfgd-writes-it.md), which also made this
hook's trigger work for a busybox client rather than only for dhcpcd.
Date: 2026-08-03
Milestone: the other hook [0061](0061-a-key-that-compiles-does-something-or-says-it-does-not.md) named

## Context

`on lease { ... }` compiled, was materialised, was hashed into the document, and
never ran -- one of the nine phases 0061 found inert and the second of the two an
operator reaches for first. [0063](0063-the-down-hooks-run-before-the-interface-goes.md)
did `down`; this is `lease`.

The difficulty is that netcfgd does not implement DHCP
([0004](0004-dhcpv4-client-sourcing.md)) and never sees the protocol. There is no
moment where a lease is handed to it. dhcpcd is started with `dhcpcd -b -4 <iface>`
and configures the interface itself; nothing reports back.

## Decision

**The trigger is an address netcfgd did not install, on an interface whose document
asks for DHCP.** That is the whole of it, and it needs no cooperation from the
client -- so it works for dhcpcd, for udhcpc, and for anything a helper writes,
which is 0045's rule that the contract is the decision and the implementation is
plural.

Three kinds of address are excluded, and each is one the kernel made rather than a
lease:

- **netcfgd's own**, by the origin it recorded and the protocol tag it wrote.
- **A link-local**, `169.254/16` or `fe80::/10` -- the second is every interface and
  the first is what a *failed* DHCP leaves behind, which is the opposite of news.
- **Anything the kernel tags as its own**: `IFA_PROTO` 1, 2 and 3 are the
  loopback's, a router advertisement's and a link-local's. The second matters most:
  a SLAAC address is not netcfgd's and is not a lease, and on a kernel older than
  5.18 there is no `IFA_PROTO` to tell it apart from one. That is
  [0002](0002-object-ownership-tagging.md)'s weakness in a second place rather than
  a new one, and the value checks above catch the common cases there.

**It fires once per lease, not once per reconcile**, and that is what the `/run`
record is for: netcfgd remembers the address it last told a hook about and compares.
Without it, a daemon would run somebody's script on every netlink event the machine
sees -- which is exactly the defect 0063 found in the *up* hooks, and the reason this
one was built with the record from the start.

**The record is written whether or not the hook succeeded.** A failing `lease` hook
that kept the plan non-empty would be a plan that never converges, against section
4's promise; the failure goes in the journal instead. That is a real trade: a script
that fails once does not get another go until the lease moves again.

**One address per interface**, the first qualifying one in canonical order. A lease
is one address; an interface carrying two that netcfgd did not install has something
else going on, and reporting the first beats inventing an order.

## What it does not do

- **The first apply of a fresh interface does not fire it.** The client is being
  started in that same plan and the address arrives seconds later. The daemon gets
  there on the netlink event; `ncfg apply --oneshot` needs a second run, which is
  the shape a `PPPoE` session already has.
- **A renewal to the same address is not a lease change**, so nothing fires.
  netcfgd cannot see renewals at all -- only addresses -- and a hook that fired on
  every renewal would need the client's cooperation, which is the thing this design
  is built to avoid needing.
- **DHCPv6 versus SLAAC on an old kernel** is the honest gap above.

## Consequences

- `NCFG_ADDR` carries the lease, which is the one thing a script wants that it
  cannot get from the interface name. It comes from the op's `address` field, added
  in 0063 for this.
- The observed schema gains `lease_hooks`, a list of `{interface, address}` -- and
  the name says what it is: not the current lease, the one a hook has been told
  about. Its witness moved: a minor addition.
- Five of the eleven phases now fire; six still say so in the plan.
- `tests/live/hooks.sh` covers it against a real kernel with a **stub client**: the
  address is put on the interface by `ip addr add`, which is what a client would
  have done, and netcfgd's reaction to the address is what is under test. A static
  address from the document sits beside it, so a comparison that forgot to exclude
  netcfgd's own would pick the wrong one and the environment check would say so.
- `+8 KB` installed, with a line in `size-budget.txt`.

## What this leaves open, and it is not small

netcfgd's `udhcpc` path is **broken on a machine with no dhcpcd**, found while
looking for a way to test this: netcfgd runs `udhcpc -b -i <iface>` with no `-s`,
and busybox's udhcpc does nothing at all without a script -- Debian ships none, so
there is no `/usr/share/udhcpc/default.script` to fall back on. The client gets a
lease and configures nothing. Fixing it means netcfgd generating a script, which is
the mechanism 0051 already uses for odhcp6c and 0048 for openvpn -- and which would
give netcfgd the lease *directly*, making this decision's address-watching the
fallback rather than the only road. That is its own piece of work and its own
decision.
