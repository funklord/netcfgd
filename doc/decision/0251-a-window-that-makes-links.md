# 0251: a window that makes links

Status: accepted
Date: 2026-09-16
Milestone: M9; the window can configure the machine

## What was left

0250 gave the window a device tab and an editor for the hardware. What it could
not do was the other half of what a `device` block is for: **a bridge, a bond, a
VLAN, a veth pair, a macvlan, a VRF, a VXLAN or a tunnel is a link netcfgd
*creates* rather than finds**, and the only way to ask for one was to write the
block by hand. The editor refused to save any device whose kind was not
`physical`, on the honest grounds that a form without the fields would empty the
block.

## The kind is a field now

The editor opens with a name, a kind, and the fields that kind needs:

| kind | what it asks for |
|---|---|
| `bridge` | members, spanning tree, vlan filtering |
| `bond` | members, mode, link check interval |
| `vlan` | parent, id, protocol |
| `veth` | the other end's name |
| `macvlan` | parent, mode |
| `vrf` | the routing table it owns |
| `vxlan` | id, parent, local, remote, port |
| `tunnel` | encapsulation, local, remote, parent |
| `dummy` | nothing |
| `physical` | nothing, and it writes nothing |

**`physical` writing nothing is the rule, not an omission.** A real adapter is a
link the kernel already has; `kind = "physical"` is the absence of a creation
rather than a creation of its own, and a block that stated it would be claiming
netcfgd makes the card.

**One form with rows that appear, not a stack of pages.** A stack was written
first and thrown away: `members` belongs to a bridge and a bond, `parent` to
four kinds, and the two tunnel addresses to two -- so a field would have had to
live on two pages, or be replaced by a label pointing at another page. Rows that
appear and disappear keep one field in one place.

**`new device...` is where a link is made**, and it is the one control in that
tab that needs no row selected, because what is being made is not in the list
yet.

## What still refuses, and why it is a shorter list

The refusal was every kind but `physical`. It is now four: `wireguard`,
`pppoe`, `openvpn` and `tun` -- a tunnel's peers and keys, a session's
credentials, a foreign configuration file -- plus `ifb`, which netcfgd
synthesises and nobody writes. Each carries something no field here holds, so
saving would delete it.

## The check that could not fail

`live_device_dialog` asserts that a VLAN with no parent is refused *by the
dialog*, before anything is sent. Written as "the note mentions `parent`" it
passed with the check removed -- because netcfgd refuses a parentless VLAN too,
and its refusal has that word in it. Measured, by deleting the check and
watching the test stay green.

What separates the two is whose sentence it is, so the assertion is now the
dialog's own words. **The fifth vacuous fixture this campaign has found, and the
second where the wrong answer and the right one were the same string.**

## Seven sabotages, all caught

A physical device writing a creation anyway; a bridge's members dropped; the
VLAN protocol written when it is the default; any device name accepted; a VLAN
with no parent sent anyway; the kind not loaded back when the editor reopens;
every kind but `physical` refused again.

The sixth is the one worth naming: a form that saved a kind and did not load it
would put every field back at its default on the next open, and `physical`
saved over a bridge deletes the bridge.
