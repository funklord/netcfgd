# 0125: Displacing NetworkManager is a runtime switch and nothing else

Status: accepted
Date: 2026-08-20
Milestone: M7's packaging; the first evaluation

## Context

M7's shim answers NetworkManager's D-Bus interfaces from netcfgd, and tiers 1
and 2 were recorded as done. What that recorded was the shim's *behaviour*,
measured against a private bus started by `tests/live/nm.sh`. It said nothing
about its *reachability*, and the shim was installed by nothing: no target, no
unit, no bus policy, no package. `nmtui` on an installed machine could not
reach netcfgd and never could have.

The holder's instruction is that netcfgd should displace NetworkManager. The
word needs pinning down before anything is built, because the obvious readings
are all destructive and the question that exposes them is "how do I get
NetworkManager back when netcfgd is not working?" -- which, on a machine whose
network has just stopped, is the only question that matters.

## Decision

**Displacement is which daemon is running. Nothing else.**

Three things it explicitly is not:

- **Not removing the `network-manager` package.** This is the reading that
  cannot be undone by the person who needs to undo it: reinstalling needs the
  network they have just lost. It is also unnecessary -- an installed
  NetworkManager that is not running costs a few megabytes of disk.
- **Not overwriting or diverting NetworkManager's files.** A `dpkg-divert` on
  `/usr/sbin/NetworkManager` would survive netcfgd's own removal and leave a
  machine with neither.
- **Not a dpkg `Conflicts:`.** That would force the removal above at install
  time, which is the same trap wearing packaging syntax.

What it is: `netcfgd-nm.service` carries `Conflicts=NetworkManager.service`,
and starting one stops the other.

## Why this is recoverable, stated as the properties it rests on

Each was measured rather than assumed, because the whole value of the decision
is that the way back works on the day it is needed:

- **`Conflicts=` is symmetric.** `systemd.unit(5)`: "starting the former will
  stop the latter and vice versa". So `systemctl start NetworkManager` stops
  the shim without the operator having to get an order right.
- **`disable`, not `stop`.** `netcfgd.service` has `Restart=on-failure`. A stop
  from the conflict is a clean stop, so starting NetworkManager does win --
  but a *crash-looping* netcfgd restarts and takes the bus name back, and
  "netcfgd is not working" is precisely that case. The documented handback
  therefore disables.
- **NetworkManager is not D-Bus activated**, so a stopped one stays stopped and
  a client call cannot resurrect it under the shim. Checked for the absence of
  a file in `/usr/share/dbus-1/system-services/`.
- **Only root may own the name**, per NetworkManager's own bus policy. The shim
  runs as root and nothing unprivileged can take the name from it.
- **NetworkManager's profiles are never touched.** Neither netcfgd nor the shim
  reads or writes `/etc/NetworkManager/system-connections`; verified by
  grepping the adapter. It comes back knowing every network it knew.

Everything in the handback is local, offline, and free of package operations.

## The shim ships its own bus policy

`packaging/dbus/netcfgd-nm.conf`, and it is not redundant with
NetworkManager's. The right to own `org.freedesktop.NetworkManager` is granted
today *by NetworkManager's own policy file*, so on a machine where that package
has been removed the grant leaves with it -- and the shim would fail to claim
the name on exactly the machine most committed to using it. A shim whose
purpose is to answer where NetworkManager used to cannot depend on
NetworkManager being installed.

It contains **only allows**. Policy files merge with later rules winning, so a
`deny` of ours could override an allow of NetworkManager's on a machine running
the real thing.

The send list is the shim's own surface rather than a copy of NetworkManager's,
which grants sends on interfaces for modems, WiMax, Bluetooth and a dozen VPN
plugins that this implements none of. `tool/dbus_policy_gate.py` reads the
interfaces out of the shim's source and fails in either direction, because the
failure is otherwise silent: a missing interface is a client method call denied
at run time, on a machine where NetworkManager's policy is absent, which is the
one configuration nobody reaches by accident.

## Enabling stays the operator's act

**The exclusive drop-in is not installed into place**, by explicit instruction.
It ships as documentation under `/usr/share/doc/netcfgd/`, and copying it into
`/etc/systemd/system/netcfgd.service.d/` is something a person does.

**Neither package enables or starts anything.** That was already the stated
intent and `debian/rules` now enforces it with `--no-enable --no-start`, which
matters most for the shim: starting it stops NetworkManager, and doing that on
`apt install` would take the machine off the network before its operator had
asked for anything.

`make deb` checks the built packages rather than the recipe. A postinst's
behaviour is appended by debhelper at build time, so what a package does on
install is only readable from the package -- and the first version of that
check could not have failed, because it looked for `deb-systemd-invoke.*start`
while the generated code says `deb-systemd-invoke $_dh_action`.

## What is deliberately left

**Both daemons enabled at once is undefined**, because `Conflicts=` carries no
ordering and the winner at boot is whichever systemd reaches first. Enabling
exactly one is documented rather than enforced: enforcing it would mean a
maintainer script disabling a service the operator enabled, which is the
package deciding something that is not its to decide.

**No OpenRC or procd equivalent.** The shim is D-Bus, which is a desktop
concern, and the two init systems that have no `Conflicts=` equivalent are the
ones on routers. If it is wanted there, it is a separate piece of work with its
own mechanism.

## Rejected

**`ncfg takeover` / `ncfg handback` subcommands.** Rejected: it would be
netcfgd stopping other people's daemons, which
`packaging/systemd/netcfgd-exclusive.conf` already refuses in a sentence worth
keeping -- "a network daemon that kills other daemons is a surprise nobody
wants to debug, and systemd already has the mechanism". Two commands the
operator can read, and undo, beat a verb that hides them.

**Shipping the shim inside the `netcfgd` package.** Rejected by constraint 3.
The daemon links no D-Bus, no glib and no polkit and is meant to build on
machines that have none; the shim brings zbus and its transitive dependencies,
and a single package would put them on every router that installs netcfgd.
