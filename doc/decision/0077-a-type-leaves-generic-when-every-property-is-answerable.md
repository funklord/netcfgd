# 0077: a type leaves `Generic` when *every* property is answerable

Status: accepted
Date: 2026-08-03
Milestone: M7 tier 3, the two device types project.md said were ready

## Context

project.md's next-steps list said:

> **The shim's remaining device types, which have everything they need now.**
> `.Device.Vlan` wants an id and a parent and `.Device.IPTunnel` a local, a
> remote and a parent; every one of those is in the observation, put there by
> 0058, 0059 and 0060 for local reasons.

Half of that is right, and the half that is wrong is the interesting half. The
list of properties was written from what netcfgd happens to observe, not from
what libnm asks for. Read off libnm's own accessors:

```
nm_device_vlan_get_carrier          nm_device_ip_tunnel_get_encapsulation_limit
nm_device_vlan_get_hw_address       nm_device_ip_tunnel_get_flags
nm_device_vlan_get_parent           nm_device_ip_tunnel_get_flow_label
nm_device_vlan_get_vlan_id          nm_device_ip_tunnel_get_fwmark
                                    nm_device_ip_tunnel_get_input_key
                                    nm_device_ip_tunnel_get_local
                                    nm_device_ip_tunnel_get_mode
                                    nm_device_ip_tunnel_get_output_key
                                    nm_device_ip_tunnel_get_parent
                                    nm_device_ip_tunnel_get_path_mtu_discovery
                                    nm_device_ip_tunnel_get_remote
                                    nm_device_ip_tunnel_get_tos
                                    nm_device_ip_tunnel_get_ttl
```

Four against thirteen. netcfgd observes all four of the first and eight of the
second: there is no encapsulation limit, no flags, no flow label, no fwmark, no
path-MTU-discovery bit and no TOS anywhere in the observation *or* in the
document, and a GRE tunnel's key is one value where NM has an input and an output
one.

## Decision

**A VLAN is a `.Device.Vlan`. An IP tunnel stays `GENERIC`.**

The rule `Flavour`'s own comment already stated is the one applied here, and this
decision is mostly about restating it precisely: a type leaves `Generic` when NM
defines an interface for it *and netcfgd can answer every property on that
interface* from what it already observes. Not the properties somebody listed --
every one. Answering six of thirteen with zeroes would be a device that claims a
type and lies about half of it, which is exactly the failure that kept
`.Device.WireGuard` unimplemented until 0054 could fill it.

**The VLAN's two interesting properties exist for local reasons**, which is
constraint 6 running in the direction it is meant to:
[0059](0059-an-interface-is-remade-when-the-kernel-will-not-change-it.md) made a
VLAN's id something the planner compares (and remakes the interface over), and
[0060](0060-a-parent-is-one-word-and-two-attributes.md) made a parent something
netcfgd sends to the kernel and reads back -- after finding that two link kinds
had never sent one at all. Nothing in the core changed for this shim, which is the
test constraint 6 sets.

The parent is served as an **object path**, which is what NM's property is, and as
`/` where the parent is not a device this shim serves. Inventing a path to a
device that is not there would have libnm fetch properties from nothing.

**The device is a VLAN; its profile is still an `802-3-ethernet`.** Those are two
different questions -- NM's `vlan` connection type carries an id and a parent in
the *connection*, which is the same information from the other side -- and every
non-radio interface block already gets the ethernet profile, a dummy included.
That is a separate piece of work and is not smuggled in here.

## What the test is worth

**Read the properties, never the TYPE column.** The WireGuard block in `nm.sh`
spells out why: `nmcli` prints a generic device's `TypeDescription`, and netcfgd's
description is the kernel's link kind -- so a generic device described as `vlan`
renders identically to a real one, and the obvious check passes with the mapping
deliberately broken. The live checks read `VlanId`, `Parent` and the numeric
`DeviceType` over the bus instead. Breaking `flavour_of` fails three of the four.

The id in the fixture is one the document chose, for the reason the WireGuard
block uses a listen port: it cannot arrive by accident and is in no other
property.

## Consequences

- `nmcli device status` shows a VLAN as `vlan`, and a settings panel switching on
  `NM_DEVICE_TYPE_VLAN` finds what it expects behind it.
- An IP tunnel still shows as `generic`, which is honest, and the reason is now in
  a test that names the six missing properties rather than in somebody's memory.
- Nothing in the core changed. `+0 KB` there; the shim is its own workspace and is
  not in the size budget.

## What is still open

**A tunnel could leave `Generic` later, and the price is named.** It needs six
things in the observation that nothing in netcfgd wants for itself today. Adding
them *for the shim* is what constraint 6 forbids; adding them because a plan needs
to compare them -- a TOS or a path-MTU-discovery bit an operator wrote down --
would make this fall out for free, exactly as the VLAN's did.

**A `vlan` connection type is the other half.** A profile that says `802-3-ethernet`
for a device NM knows is a VLAN is not wrong, but a panel offering to edit the tag
would need the connection to carry it. Same shape as the static-addressing
round-trip in [0033](0033-nm-splits-what-netcfgd-keeps-together.md), and worth
doing when something asks.
