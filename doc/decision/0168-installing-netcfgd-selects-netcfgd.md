# 0168: installing netcfgd selects netcfgd

Status: accepted
Date: 2026-09-07
Milestone: M8; instructed by the copyright holder

Reverses the principle stated in `debian/postinst`, `debian/prerm` and
`debian/rules`, and supersedes the opt-in half of
[0125](0125-displacing-networkmanager-is-a-runtime-switch-and-nothing-else.md).

## The instruction

"When netcfgd is installed I want it to work 100%, and any other processes
that interfere with it are to be killed, disabled and if they still persist,
renamed." And, on being told NetworkManager could not simply be removed:
"We keep NM around only because many desktops have a built in
wireless/network configurator applet for NM which works with netcfgd-nm too,
but depends on NM."

## What was there before

The packaging said, in three places, that installing a package must not
decide that this machine's other network daemons stop. The unit shipped
disabled, nothing was started, and the exclusive drop-in shipped to
`/usr/share/doc`. A machine that installed netcfgd therefore got a program
that did nothing until three further commands were run, and one that lost
every argument with whatever was already holding the interfaces.

That is a defensible position and it is not the one the holder wants. It is
reversed here rather than contradicted quietly: the headers that stated it now
state this, and say which record changed them.

## Decision

**`netcfgd_select.sh` chooses which daemon owns the network, and `postinst`
runs it.**

    netcfgd_select.sh [netcfgd|networkmanager|networkd|none]

A script rather than a block of `systemctl` calls in `postinst`, because it
has to run in the other direction too: `prerm` calls it with `none` on the way
out, and an operator who wants NetworkManager back for an afternoon runs one
command rather than reconstructing a dozen from memory. **A takeover with no
way back is what leaves a machine unusable.**

**It stands down services. It does not touch packages or binaries.**

- **The NetworkManager package stays.** Desktop wireless applets depend on it
  and work against netcfgd through `netcfgd-nm`, which serves NM's own bus
  name and object tree. What cannot run is the NM *daemon*, because two
  processes cannot own one bus name.
- **netcfgd delegates to eight programs** -- `wpa_supplicant`, `dhcpcd`,
  `hostapd`, `pppd`, `openvpn`, `udhcpc`, `odhcp6c`, `resolvconf` -- and
  `dnsmasq` and `unbound` are DNS backends 0007 offers as modes. Disabling any
  of those breaks netcfgd rather than its competition. `wpa_supplicant` and
  `dhcpcd` are the two that live in both worlds: the *service* is a rival
  instance another manager drives, the *binary* is netcfgd's to run, and the
  script tells them apart by the `/run/netcfgd/` marker in the process's own
  argv (0140).

**Renaming is not done, and the reason is measured rather than squeamish.**
A plain rename is undone by the next `apt upgrade` of the package that owns
the file, and `dpkg-divert` is the mechanism that makes one persist. But
crossing the divertible daemons against the two lists above leaves
`connmand` and `dhclient` -- and neither is what contests a modern desktop.
The daemons that fight netcfgd are precisely the ones it delegates to or
impersonates. **Masking is the rung that does the work**, it survives reboots
and upgrades, and it is reversible; rename would be ceremony with a package
database to repair afterwards.

## Beyond stop and disable

Stopping a network daemon does not undo what it left, and the leftovers are
what make the next daemon fail unreadably:

- **Its runtime claim.** NetworkManager writes
  `/run/NetworkManager/devices/<ifindex>` and systemd-networkd writes
  `/run/systemd/netif/links/<ifindex>`; neither is removed on stop. netcfgd
  reads both to decide whether somebody else holds an interface, so a stopped
  NM went on holding every interface for ever -- [0145](0145-a-stopped-daemon-leaves-its-claim-behind.md),
  the report that cost days, where the guard against two daemons fighting
  produced a machine with no daemon at all.
- **Its children.** A supplicant or DHCP client started by NM is not stopped
  with NM, so the radio stays held by a process whose parent is gone.

**`ifupdown`'s `/run/network/ifstate` is deliberately not treated as a
claim**, and the first draft had it. It is not stale state, it is ifupdown's
live record of which interfaces it brought up, and netcfgd never reads it --
so removing it buys netcfgd nothing and costs ifupdown the ability to bring
those interfaces down. Caught by running `--dry-run` on the development
machine, where it proposed deleting the entries for `eth0`, `ib0` and `lo`.

**netplan is warned about rather than acted on.** It is not a daemon: it
renders `/etc/netplan/*.yaml` into networkd or NM configuration at boot.
Masking those two stops them, but the yaml outlives this, so anybody who
unmasks them later gets netplan's idea of the network back. Removing somebody
else's declarative configuration is not this script's business.

## Consequences

- `postinst` selects netcfgd **only on a first install**. An upgrade must not
  re-take a machine whose operator has since chosen NetworkManager -- they ran
  the switcher and meant it, and an upgrade that undid that would make the
  switcher a lie.
- **The unmasking is in `prerm`, not `postrm`.** For `remove`, dpkg deletes
  the package's files and *then* runs `postrm`, so the switcher would already
  be gone, the `-x` guard would skip silently, and the machine would keep
  every network daemon masked with nothing left able to unmask them. The first
  draft of this change put it in `postrm` and would have failed exactly that
  way.
- `--dry-run` works without root. Refusing it would leave the one mode an
  operator can use to find out what this does available only to the account
  that no longer needs to ask.
- `tool/select_gate.py` runs in `make check`. The script keeps four facts per
  daemon and three live in `case` arms, so a manager added to the list and to
  two of the three is silently never stood down -- a fall-through reads
  exactly like a daemon with nothing to clean up. It also refuses a unit named
  for a program netcfgd runs itself.

## What is untested here

The development machine has no systemd, so every `systemctl` path is exercised
only through `--dry-run`. What has been run is the argument handling, the
refusal without root, all three directions of selection, and the gate. A
machine with systemd is what would prove the rest, and that is the same bar
§10's *What would prove it* sets for the daemon itself.
