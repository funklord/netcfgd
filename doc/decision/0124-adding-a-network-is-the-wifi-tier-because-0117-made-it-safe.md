# 0124: Adding a network is the wifi tier, because 0117 made it safe

Status: accepted
Date: 2026-08-20
Milestone: M8's desktop half; the first evaluation

Supersedes the `admin, not wifi` bullet of
[0117](0117-adding-a-network-is-a-typed-request-not-a-written-file.md), and
closes the gap [0013](0013-three-things-a-caller-may-be-allowed-to-do.md)
named and left open. Nothing else in either record changes.

## Context

An operator installed netcfgd, joined the `netcfgd` group, and could not
configure wifi. Three things were in the way at once; two were defects and
are fixed alongside this. This is the third, and it is not a defect -- it is
a decision that had outlived its reason.

The tier system says who may do what, and `wifi_add` was `admin`. `admin` is
"change anything else", which on a default install is root. So a desktop user
could scan, could join a network somebody had already written down, and could
not add the network they were standing in front of. Every new cafe, every new
office, every new phone hotspot needed a root shell -- which is the exact
failure 0117 opened with and set out to fix.

0117 fixed the *transport* and left the *tier* alone, and the tier is what
was refusing.

## Why the old placement was right when it was made

0013 drew the wifi tier as "scanning, and joining or leaving a network **that
is already in the configuration**", and reasoned that creating one means
writing config, that config is the source of truth, and that a tier which
could write config would be `admin` wearing a hat.

That reasoning was correct about the mechanism available at the time. Writing
config meant writing a *file*, and a config file can name a hook. A hook's
`run_as` is absent by default, which means root. So anything able to write
arbitrary config into `/etc/netcfgd` can run arbitrary code as root, whatever
the file's mode says. Handing that to a desktop group would have been handing
it root, and 0117 rejected the group-writable config directory for exactly
this reason -- "the cheapest option is the one that quietly grants the most."

**0013 did not treat this as settled.** It named the consequence a gap in the
same paragraph, pointed at design section 9.4 as the shape of an answer, and
wrote: "Until that exists, adding a network is `admin`." That sentence is a
placeholder with a condition attached, and the condition has been met.

## What changed underneath it

0117 built a mechanism 0013 did not have: a typed `wifi_add` request carrying
an SSID and a passphrase, never config text and never a path. Its own
sentence is the whole argument:

> **A request that carries config text is remote code execution. A request
> that carries an SSID and a passphrase is not.**

The daemon renders the `network` block itself. The request has no field that
could name a hook, a path, a `run_as`, an interface, a device, or a control
policy, because those are not fields it has -- the privilege is bounded by
the shape of the message rather than by the caller's manners.

So after 0117 the danger the old placement was avoiding does not exist on
this path. What kept `wifi_add` in `admin` was 0013's *definition* of the
wifi tier, quoted forward into 0117's bullet as though it were the security
argument. It was not. It was a description of what the tier covered when the
tier was drawn, and a definition is ours to redraw when the thing it
described has changed.

## Decision

**`wifi_add` is the `wifi` tier.** The tier is now: scan, join, leave, and
add.

## What this grants, exactly

Worth stating precisely, because "may write configuration" is the phrase that
made this sound larger than it is:

- **One `network` block, and one secret at 0600.** Nothing else is
  expressible.
- **Inbound only.** The passphrase travels in the request, is written through
  the secret provider, and the block keeps an `@secret:` reference. Reading
  one back is refused: `GetSecrets` refuses and 0031's bridge runs one way.
  The desired-state document stays free of secret material (constraint 5).
- **Adding is not applying.** `Apply`, `Confirm`, `Revert` and `Reload` stay
  `admin`. A wifi-tier caller adds a network and joins it with
  `WifiConnect`, which was already theirs; it cannot apply an unrelated
  configuration change, and the daemon picking the new file up on its own is
  the reload it already does for any edit.
- **Not `any` by default.** Every tier still defaults to root. This changes
  what the wifi tier *covers*, not who holds it, and a machine that never
  writes a `control` block behaves exactly as before.

What a wifi-tier caller can now do that it could not: accumulate `network`
blocks and secrets in `/etc/netcfgd`. That is the honest cost. It is clutter
and disk in a directory an operator can read, by a named group somebody was
deliberately put into -- against a laptop that needed a root shell for every
new network it met.

## The CLI is a separate path and is unchanged

`ncfg wifi add` writes the two files itself rather than asking the daemon, so
it still needs write access to `/etc/netcfgd` and a group member running it
still gets `EACCES`. That is not fixed here. This decision is about the
socket, which is what the GUI and the TUI use, and routing the CLI's own
`add` through the daemon when it cannot write is its own piece of work --
with its own question attached, since the socket has no enterprise (802.1X)
arm and `ncfg wifi add --eap` therefore cannot cross it.

## Rejected

**A fourth tier**, so that adding is neither `wifi` nor `admin`. Rejected:
0013 chose three because they are the three questions operators actually
have, and it refused a rule language for the same reason. A tier that exists
to hold one request is a rule language with four values.

**Leaving it and documenting the workaround** -- grant `admin` to the desktop
group. Rejected: `admin` is apply, revert and reload, so this hands over the
whole machine's networking to avoid moving one request. It is also what the
postinst was telling people to do, which is how the shape of a permission
system gets decided by a line of shell nobody reviewed.

**Making `wifi_add` conditional** -- allowed for a network in range, refused
otherwise. Rejected: it makes authorisation depend on the radio's current
view of the world, so the same request succeeds and fails for reasons no
config file explains, and a hidden network could never be added at all.
