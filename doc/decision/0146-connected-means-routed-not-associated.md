# 0146: connected means routed, not associated

Status: accepted
Date: 2026-08-28
Milestone: M8; the tray, and what an icon is allowed to claim

## The report

"We also want the gui to have a tray that faithfully shows if we're connected
or not." The word doing the work is *faithfully*, and it was earned: the tray
drew green whenever the supplicant had joined a network.

## What was wrong

Association is the earliest of four steps and the least informative. A radio
can be associated with an access point and have no address, or an address and
no route -- and on the machine that reported this, the tray would have shown
connected while netcfgd managed nothing on that interface at all, the address
belonging to an adopted dhcpcd and `/etc/resolv.conf` still carrying what a
stopped NetworkManager left behind.

The wired path was better and still wrong: it asked whether any interface had
an address. An address with nothing to route through is a machine that fails
every request while looking configured.

## Decision

**The icon reports the furthest rung actually reached, and there are three.**

    offline   no address, or a radio that has joined nothing
    local     addressed, with no default route to leave through
    routed    a default route in the main table

`local` is the state that used to draw as connected, and it is the one an
operator most needs to see: a radio that joined a network and never got a
usable route looks identical to a working one from every other angle. The
tooltip names it -- "no default route", or "joined, no address".

**A boolean cannot express this, so the type is not one.** `ncfg_reach` is an
enum, and `painted_icon`/`state_icon` take it. The alternative considered was
keeping the boolean and choosing a better predicate, which would have collapsed
`local` into one neighbour or the other and lost the distinction the report was
about.

**Table 254 only.** A default route in another table is reached through a
policy rule and says nothing about where this machine's ordinary traffic goes.
Counting it would tell an icon that a host with one rule and no uplink was
connected.

**Ownership is not consulted.** A route netcfgd did not install still carries
packets. An icon that went grey because another daemon put the route there
would be reporting on netcfgd rather than on the machine, which is not what a
tray is for.

## The ceiling, and why it is not called `online`

**`routed` is the last thing observable without sending a packet**, and it is
deliberately not named for connectivity. Whether anything answers needs a host
to ask, and [0061](0061-a-key-that-compiles-does-something-or-says-it-does-not.md) declined
to have netcfgd choose one: a default would be a third party told when this
machine joins a network. A `portal_check` URL is the operator's to set, and an
icon built on it would be reporting on a URL rather than on the machine.

So the honest claim is "there is somewhere for traffic to go", and the name
says that rather than promising more.

## What this cost to get wrong

The same machine, the same afternoon: netcfgd running, NetworkManager stopped
by the exclusive drop-in, the radio associated at -40 dBm and passing traffic,
every address and route on it `[Foreign]`, and DNS served by a file NM wrote
before it was stopped. Under the old rule the tray was green throughout. The
operator's question -- "something is blocking dhcp or dns" -- was asked from in
front of an icon saying everything was fine.

## Enforcement

`gui/tests/tray_icon.cpp` renders all three and asserts they are three distinct
pictures in three distinct colours, none carrying another's. A middle state
that drew as either neighbour would be read as that neighbour, which is the
failure this record exists to prevent, and it would pass a test that only
checked that something was drawn.
