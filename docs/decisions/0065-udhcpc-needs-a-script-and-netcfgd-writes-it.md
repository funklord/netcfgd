# 0065: udhcpc needs a script, and netcfgd writes it

Status: accepted
Date: 2026-08-03
Milestone: the defect [0064](0064-a-lease-is-an-address-netcfgd-did-not-install.md) turned up

## Context

Found while looking for a way to test the `lease` hook: **netcfgd's DHCPv4 fallback
did nothing at all.** It ran

```
udhcpc -b -i eth0
```

and busybox's client has no configuration step of its own. It obtains a lease, sets
the lease in the environment, and runs `$1` of the script named by `-s`. Without
one it falls back to `/usr/share/udhcpc/default.script`, which **Debian does not
ship** -- busybox's package contains no udhcpc script at all. So on a machine with
busybox and no dhcpcd, `config = "dhcp"` got a lease and configured nothing, and the
plan said `backend.start` and reported success.

Two more halves of the same defect, both found by writing the test:

- **The client could not be found by name.** Debian packages busybox as one binary
  with no `udhcpc` symlink, so `Command::new("udhcpc")` fails on exactly the
  machines the fallback exists for.
- **The client could not be stopped.** `stop_backend` ran `dhcpcd -k <iface>`, which
  does nothing to a udhcpc, and there was no pid file to find one by. A
  `backend.stop` -- from teardown, or from a recreation (0059) -- left the client
  running.

Nothing in the suite had ever driven a v4 client, which is how all three survived.

## Decision

**netcfgd generates the script**, under `/run/netcfgd/udhcpc/<iface>.script`,
regenerated on every apply, and passes it with `-s`. Also `-p` for a pid file and
`-R` so a stopped client releases its lease. The candidate list grows a third entry,
`busybox udhcpc`, so the applet is reachable where the symlink is not.

**The script does what dhcpcd does, and no more**: the address and the default
route, untagged. The lease belongs to the client exactly as dhcpcd's does
([0004](0004-dhcpv4-client-sourcing.md)), netcfgd treats both the same way, and the
`lease` hook (0064) needs no case for either -- it fires off an address netcfgd did
not install, whichever client installed it.

Three things it deliberately does not touch:

- **The MTU**, which the document owns. A lease that lowered it would have netcfgd
  fighting its own `mtu` field on every renewal.
- **`/etc/resolv.conf`**, which netcfgd's DNS backends own. A client writing it
  behind netcfgd's back is the contention this project exists to avoid. What to do
  with a lease's nameservers is one decision for both clients and is not this one.
- **Every address it did not add.** A stock `deconfig` flushes the interface; this
  one records the address it added and removes exactly that. `tests/live/dhcp.sh`
  puts a static address on the same interface for this reason, and breaking the
  guard fails both that check and the unit test that reads the generated script.

`$mask` is the prefix length and `$subnet` the dotted form -- both arrive, and the
script uses the one `ip` takes. A client old enough to set only `subnet` is refused
by name rather than guessed at.

## What the test is worth

`tests/live/dhcp.sh` is a real exchange: `busybox udhcpd` on the far end of a veth
pair, netcfgd's own generated script on the near end, a real DISCOVER/OFFER/
REQUEST/ACK, and a real lease on the interface. It needs no package a machine with
busybox does not already have, which is why it can be in the ordinary suite rather
than behind a skip.

Everything about the environment was measured rather than taken from a manual page,
including `$mask` -- which is what made the script correct on the first run against
a real client.

## Consequences

- `config = "dhcp"` works on a machine with busybox and no dhcpcd, which is most
  Debian machines that have not installed one.
- A `backend.stop` stops a udhcpc, and the address goes with it: `-R` makes the
  client release the lease and run `deconfig` on `SIGTERM`, which without it it does
  not -- measured, and the reason a stopped client used to leave its address behind.
- The pid is checked against `/proc/<pid>/cmdline` before anything is signalled, for
  the reason `pppd_pid` does it: a pid file outlives the process it names and pids
  are recycled.
- `+0 KB` measured: the script is a format string and the rest is a handful of
  arguments, which the 3% tolerance absorbs.

## What is still open

**A lease's nameservers reach nothing.** Neither client tells netcfgd about them --
dhcpcd writes `resolv.conf` through its own hooks if configured to, and this script
deliberately does not. So `config = "dhcp"` gives an address and a route, and DNS
comes from the document. The fix is one decision covering both clients: the report
contract ([0047](0047-a-tunnels-address-stays-with-its-daemon.md)) already has a
`dns` key and a gate for exactly this
([0049](0049-a-server-may-name-resolvers-not-where-queries-go.md) says a reported
nameserver needs the interface to have asked), so the shape exists -- what it needs
is dhcpcd's half, which means a dhcpcd hook script and a decision about writing one
into `/etc` or `/libexec`.
