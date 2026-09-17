# 0254: the link that is not a netlink message

Status: accepted
Date: 2026-09-17
Milestone: M9; the window can configure the machine

## The kind that was in the schema and not implemented

`InterfaceKind::Tun` has been in the model since the beginning with a comment
saying why it was not built:

```quote from=crates/netcfgd-sys/src/tun.rs
comes from a TUNSETIFF ioctl on /dev/net/tun
```

Every other virtual link netcfgd makes is an `RTM_NEWLINK` with a kind name in
it. A tun or tap device is not: it comes from an ioctl on a clone device, and
it exists only while something holds that descriptor unless `TUNSETPERSIST` is
set on it. An ioctl is `unsafe`, `unsafe` lives in one audited crate, and so
the kind stayed in the schema with the executor refusing it and telling the
operator to run `ip tuntap add` themselves.

**That was a wall made of a rule, and the rule already had the answer in it.**
The one crate permitted `unsafe` is where the libc boundary lives -- the
terminal size and `SO_PEERCRED` are in it, and neither is netlink. So
`netcfgd_sys::tun` is three ioctls in the place the policy already points at,
and the hole in the configuration language closes.

## What it does, in `ip tuntap add`'s order

Open `/dev/net/tun`, `TUNSETIFF` with the name and the mode, `TUNSETOWNER` and
`TUNSETGROUP` where the document names them, then `TUNSETPERSIST` and close.

Two orderings in that are load-bearing, and both are in the code as comments
because both are silent when wrong:

* **Owner and group before persistence.** A device that cannot be given the
  owner the document asked for is not left behind: closing the descriptor
  without persisting removes it. Measured -- asking for a uid that is not
  mapped in the namespace fails with `EINVAL`, and no link remains.
* **Persistence last, and it is the reason the device survives the function.**
  Sabotaging it away produces exactly the failure the comment predicts: the
  apply reports `link.create` as done and the next action fails with no such
  device.

`IFF_NO_PI` always, which is what `ip tuntap add` does without saying so. Without
it every packet carries a four-byte protocol header nothing else expects, and
the device looks subtly wrong to whatever attaches rather than failing to
appear.

## Both modes, one kind name

The kernel registers one `rtnl_link_ops` for tun and tap alike, so
`IFLA_INFO_KIND` says `tun` whichever was asked for and the mode is visible only
in the link's own nest -- `ip -d` prints `tun type tap`. Three consequences,
each handled where it lands:

* The planner's recreate check compares `tun` for both, so it catches a `tun`
  block whose name is held by something else and **does not** catch a block
  changed from `tun` to `tap`. Recorded rather than worked around: telling them
  apart needs `IFLA_TUN_TYPE`, which the observation does not read.
* The window offers `tun` and `tap` as two kinds, because which one you want is
  the question an operator is answering -- and the config language agrees, since
  the block's *name* is the mode.
* Opening an existing tap therefore has to put the pair back together: the
  document says `tun` with a mode beside it. A form that read the kind alone
  would open a tap as a tun and save it as one, which is a device silently
  replaced by the other sort.

## Five sabotages, all caught

The device not made to persist; a tap made as a tun; the owner never set; the
block's name no longer the mode; a tap opening as a tun in the editor.

The first is the one worth keeping: it fails as `link.up` on a device that is
no longer there, which is precisely what the ordering comment says it would.

## What this closes

0019's audit of foreign formats listed six gaps and left one open -- "tun/tap:
in the schema; needs an ioctl". That row is the last of the six, and this is it
closed. What remains unwritable from the window is `ifb` alone, which netcfgd
synthesises for ingress shaping and nobody writes by hand.
