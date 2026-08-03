# 0060: A parent is one word and two attributes

Status: accepted
Date: 2026-08-03
Milestone: the defect the shim's device types walked into

## Context

project.md's next item was the NetworkManager shim's remaining device types:
`.Device.Vlan` wants an id and a parent, `.Device.IPTunnel` a local and a remote.
[0058](0058-a-change-carries-the-whole-nest.md) and
[0059](0059-an-interface-is-remade-when-the-kernel-will-not-change-it.md) had
already put the id and the endpoints in the observation for local reasons, so the
only piece missing was the parent -- and constraint 6 says a field is added
because a local user wants it, never because an adapter does.

Looking for the local reason found a defect instead, in the half nobody had asked
about: **netcfgd was not sending a parent to the kernel at all** for two of the
four kinds that have one.

```
interface vx100 { vxlan  { id = 100; parent = "base0"; ... } }
interface gre1  { tunnel { mode = "gre"; parent = "base0"; ... } }
$ ncfg apply
$ ip -d link show vx100 | grep -o 'dev base0' || echo '(no underlay)'
(no underlay)
$ ip link show gre1 | head -1
18: gre1@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> ...
```

The document named a parent, the apply succeeded, and the kernel routed the outer
packets itself. It had been that way for as long as either kind has existed here.

## What the kernel actually reads

**The outer `IFLA_LINK` is not where every kind takes its parent.**

| kind | where the kernel reads the parent | where it reports it |
|---|---|---|
| vlan | outer `IFLA_LINK` | outer |
| macvlan | outer `IFLA_LINK` | outer |
| gre, gretap, ip6gre | `IFLA_GRE_LINK`, in the nest | outer |
| ipip, sit, ip6tnl | `IFLA_IPTUN_LINK`, in the nest | outer |
| vxlan | `IFLA_VXLAN_LINK`, in the nest | **in the nest** |
| geneve | nowhere -- it has none | -- |

netcfgd sent the outer attribute for all of them. A VLAN and a macvlan therefore
worked; a tunnel and a VXLAN silently did not.

**And a VXLAN is the one kind that does not report it outside either**, so the
reading half has the same split as the writing half: the observation takes the
parent from the outer attribute for every kind and falls back to the VXLAN's nest.
That asymmetry is measured and is the reason both halves have a comment saying so.

**A geneve tunnel has no underlay at all.** There is no attribute for one in its
family and `ip` offers no `dev` for it either, so a `parent` on a geneve could
only ever be dropped. It is now a compile error naming the line, which is where
0058's endpoint-family check already lives.

## And what it does with a changed one

Asked, one kind at a time, on a live device:

| kind | a moved parent |
|---|---|
| vxlan | **changes it** |
| gre (and the other tunnels) | **changes it** |
| vlan | **accepts and ignores** |
| macvlan | **accepts and ignores** |

The split is the same one as the write path, and for the same reason: what lives
in the nest is what `changelink` reads, and what lives outside is not.

So one word in the document gets both remedies that already exist:

- A **VXLAN's or a tunnel's** parent is part of the nest 0058 sends whole, so it
  is compared and set in place.
- A **VLAN's or a macvlan's** parent joins 0059's list of things that can only be
  corrected by remaking the interface.

A parent the document does not name is not compared, which matters more here than
for most fields: a tunnel with no `parent` sends its outer packets through the
routing table and the kernel reports whichever interface that chose. Comparing
that against the document's silence would rebuild the tunnel on every reconcile.

## Consequences

- `parent = "base0"` on a VXLAN or a tunnel does what it says. This is a
  behaviour change for anyone who wrote one and got a device without an underlay:
  their next `ncfg apply` moves the tunnel onto the interface they named.
- A moved parent is applied -- in place for two kinds, by remaking the interface
  for the other two -- and reported either way.
- A `parent` on a geneve tunnel is a compile error rather than a line that means
  nothing.
- `NewLink::Tunnel` becomes a struct, `TunnelSpec`, because six positional fields
  and a seven-argument encoder is where a transposed pair of same-typed addresses
  goes unnoticed. The macvlan mode's numbering, which the executor still carried
  as its own copy of 1/2/4/8, now goes through `MacvlanMode::number` -- the
  observer already read it back through the inverse.
- The observed schema gains `ObservedLink::parent`; its witness moved. A minor
  addition, and the one the shim's `.Device.Vlan` was waiting for -- which it now
  gets for a reason that has nothing to do with the shim.

## What this leaves for the shim

`.Device.Vlan` can be projected: the id and the parent are both observed.
`.Device.IPTunnel` can be projected: the local and the remote are observed, and so
is the parent. Neither needs a model change, which is the whole point of doing it
in this order.
